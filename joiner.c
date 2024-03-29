#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include "packet-struct.h"
#include "state.h"

#define SKIP_AMOUNT 80
#define SEARCH_LIMIT 20

static char *types[] = {
        "PACKET_UNKNOWN",
        "PACKET_ERROR",
        "PACKET_NAND_CYCLE",
        "PACKET_SD_DATA",
        "PACKET_SD_CMD_ARG",
        "PACKET_SD_RESPONSE",
        "PACKET_SD_CID",
        "PACKET_SD_CSD",
        "PACKET_BUFFER_OFFSET",
        "PACKET_BUFFER_CONTENTS",
        "PACKET_COMMAND",
        "PACKET_RESET",
        "PACKET_BUFFER_DRAIN",
        "PACKET_HELLO",
};

struct pkt packet_buffer[SKIP_AMOUNT];

static const char *states[] = {
    "ST_UNINITIALIZED",   // Starting state
    "ST_SEARCHING",       // Searching for either a NAND block or a sync point
    "ST_JOINING",         // Found NAND block, joining data
    "ST_DRAINING",        // Found NAND block, just copying
    "ST_BACKTRACK",   // Hit a seek point, so copying data before last NAND block
    "ST_DONE",            // Finished operation
    "ST_OVERFLOWED",      // FIFO overflowed, we'll be doing another loop
};

enum prog_state {
    ST_UNINITIALIZED,   // Starting state
    ST_SEARCHING,       // Searching for either a NAND block or a sync point
    ST_JOINING,         // Found NAND block, joining data
    ST_DRAINING,        // Found NAND block, just copying
    ST_BACKTRACK,   // Hit a seek point, so copying data before last NAND block
    ST_DONE,            // Finished operation
    ST_OVERFLOWED,      // FIFO overflowed, we'll be doing another loop
};


static int st_uninitialized(struct state *st);
static int st_searching(struct state *st);
static int st_joining(struct state *st);
static int st_draining(struct state *st);
static int st_backtrack(struct state *st);
static int st_done(struct state *st);
static int st_overflowed(struct state *st);

static int (*st_funcs[])(struct state *st) = {
    [ST_UNINITIALIZED]  = st_uninitialized,
    [ST_SEARCHING]      = st_searching,
    [ST_JOINING]        = st_joining,
    [ST_DRAINING]       = st_draining,
    [ST_BACKTRACK]      = st_backtrack,
    [ST_DONE]           = st_done,
    [ST_OVERFLOWED]     = st_overflowed,
};

/* Pulls a packet out of the buffer.
 * It pulls it out of the given offset.
 */
static int buffer_get_packet(struct state *st, struct pkt *pkt) {
    memcpy(pkt, &packet_buffer[(st->buffer_offset+st->search_limit)%SKIP_AMOUNT], sizeof(*pkt));
    st->buffer_offset++;
    st->buffer_offset %= SKIP_AMOUNT;
    return 0;
}

static int buffer_unget_packet(struct state *st, struct pkt *pkt) {
    st->buffer_offset--;
    if (st->buffer_offset < 0)
        st->buffer_offset = SKIP_AMOUNT-1;
    return 0;
}

static int buffer_put_packet(struct state *st, struct pkt *pkt) {
    st->buffer_offset++;
    st->buffer_offset %= SKIP_AMOUNT;
    memcpy(&packet_buffer[(st->buffer_offset+st->search_limit)%SKIP_AMOUNT],
            pkt,
            sizeof(*pkt));
    return 0;
}


static int is_ib_command(struct state *st, struct pkt *pkt) {
    return (pkt->header.type == PACKET_COMMAND
            && (pkt->data.command.cmd[0] == 'i'
            &&  pkt->data.command.cmd[1] == 'b')
            );
}

static int is_sync_point(struct state *st, struct pkt *pkt) {
    return ((pkt->header.type == PACKET_HELLO)
    || (pkt->header.type == PACKET_COMMAND
            && (pkt->data.command.cmd[0] == 'i'
            &&  pkt->data.command.cmd[1] == 'b'
            &&  pkt->data.command.arg == 0))
    || (pkt->header.type == PACKET_COMMAND
            && (pkt->data.command.cmd[0] == 'i'
            &&  pkt->data.command.cmd[1] == 'b'
            &&  pkt->data.command.arg == 4026531839))
    );
}

static int is_nand(struct state *st, struct pkt *pkt) {
    return (pkt->header.type == PACKET_NAND_CYCLE);
}

static int open_files(struct state *st, char *infile, char *outfile) {
    st->fd = open(infile, O_RDONLY);
    if (st->fd == -1) {
        perror("Unable to open input file");
        return 2;
    }

    st->out_fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (st->out_fd == -1) {
        perror("Unable to open output file");
        return 3;
    }
    return 0;
}


// Initialize the "joiner" state machine
static int jstate_init(struct state *st) {
    st->is_logging = 0;
    st->st = ST_SEARCHING;
    st->last_run_offset = 0;
    st->join_buffer_capacity = 0;
    st->buffer_offset = -1;
    st->search_limit = 0;
    return 0;
}

static int jstate_state(struct state *st) {
    return st->st;
}

static int jstate_set(struct state *st, enum prog_state new_state) {
    printf("jstate: %s -> %s\n", states[st->st], states[new_state]);
    st->st = new_state;
    return 0;
}

static int jstate_run(struct state *st) {
    return st_funcs[st->st](st);
}



// Dummy state that should never be reached
static int st_uninitialized(struct state *st) {
    printf("state error: should not be in this state\n");
    return -1;
}

// Searching for either a NAND block or a sync point
static int st_searching(struct state *st) {
    struct pkt pkt;
    int ret;
    while ((ret = packet_get_next_raw(st, &pkt)) == 0) {
        if (is_sync_point(st, &pkt)) {
            jstate_set(st, ST_BACKTRACK);
            packet_unget(st, &pkt);
            break;
        }
        else if (is_nand(st, &pkt)) {
            jstate_set(st, ST_JOINING);
            packet_unget(st, &pkt);
            break;
        }

        // If it's a regular "IB" command, we're re-syncing.  Backtrack to
        // here later on.
        else if (is_ib_command(st, &pkt)) {
            packet_get_next_raw(st, &pkt);
            st->last_run_offset = lseek(st->fd, 0, SEEK_CUR);
        }
    }

    // -2 is the EOF error.  Backtrack and fill things out.
    if (ret == -2) {
        jstate_set(st, ST_BACKTRACK);
        return st_backtrack(st);
    }

    return ret;
}

// Go back to the previous sync point, then read everything from there to
// the current sync point, not including the NAND blocks.
static int st_backtrack(struct state *st) {
    struct pkt pkt;
    int ret;
    int before_nand = 1;
    
    ret = lseek(st->fd, st->last_run_offset, SEEK_SET);
    if (-1 == ret) {
        perror("Unable to backtrack");
    }

    // Read every packet from the last 
    while ((ret = packet_get_next_raw(st, &pkt)) == 0) {

        // Eventually we'll hit the sync point that brought us here.
        // Return to searching.
        if (is_sync_point(st, &pkt)) {
            if (pkt.header.type == PACKET_HELLO) {
                pkt.header.sec = 0;
                pkt.header.nsec = 0;
                packet_write(st, &pkt);
            }
            jstate_set(st, ST_SEARCHING);
            st->last_run_offset = lseek(st->fd, 0, SEEK_CUR);
            break;
        }

        else if (is_nand(st, &pkt))
            before_nand = 0;

        else {
            int nsec_dif, sec_dif;
            if (before_nand) {
                sec_dif = st->last_sec_dif;
                nsec_dif = st->last_nsec_dif;
            }
            else {
                sec_dif = st->sec_dif;
                nsec_dif = st->nsec_dif;
            }

            if (nsec_dif > 0) {
                pkt.header.nsec += nsec_dif;
                if (pkt.header.nsec > 1000000000L) {
                    pkt.header.nsec -= 1000000000L;
                    pkt.header.sec++;
                }
                pkt.header.sec += sec_dif;
            }
            else {
                pkt.header.nsec -= nsec_dif;
                if (pkt.header.nsec <= 0) {
                    pkt.header.nsec += 1000000000L;
                    pkt.header.sec--;
                }
                pkt.header.sec -= sec_dif;
            }

            // Fudge the time for the "reset card" command
            // (due to timing weirdness, it can vary widely.)
            if (pkt.header.type == PACKET_COMMAND
             && pkt.data.command.cmd[0] == 'r'
             && pkt.data.command.cmd[1] == 'c') {
                pkt.header.sec = 0;
                pkt.header.nsec = 8;
            }

            if (pkt.header.sec < 0)
                printf("!!! Warning: header.sec < 0: %d\n", pkt.header.sec);
            if (pkt.header.nsec < 0)
                printf("!!! Warning: header.nsec < 0: %d\n", pkt.header.nsec);

            st->last_sec = pkt.header.sec;
            st->last_nsec = pkt.header.nsec;
            packet_write(st, &pkt);
        }
    }
    return ret;
}

static int st_done(struct state *st) {
    printf("Finished\n");
    return 1;
}

static int st_overflowed(struct state *st) {
    printf("Overflowed not supported\n");
    return 1;
}

static int st_draining(struct state *st) {
    printf("Draining not supported\n");
    return 1;
}

static int fill_buffer(struct state *st, struct pkt *pkts, int count, int
        (*get_data)(struct state *st, struct pkt *arg)) {
    int i;
    for (i=0; i<count; i++) {
        get_data(st, &pkts[i]);
    }
    return 0;
}

static int empty_buffer(struct state *st, struct pkt *pkts, int count, int
        (*unget_data)(struct state *st, struct pkt *arg)) {
    int i;
    for (i=0; i<count; i++) {
        unget_data(st, &pkts[i]);
    }
    return 0;
}


// We hit a "NAND" packet.  This means we should write out data to the
// output file.
// If this is a new stretch of joining, just write packets out.
// If it's a continuation, try to match up the output.
#define REQUIRED_MATCHES (SKIP_AMOUNT*30/100)
static int st_joining(struct state *st) {
    struct pkt pkt;
    int ret;

    // Actually attempt to join the data
    if (st->buffer_offset >= 0) {
        struct pkt pkts[REQUIRED_MATCHES];
        struct pkt old_pkts[REQUIRED_MATCHES];
        int synced = 0;
        int disk_offset = 0;
        int buffer_start = st->buffer_offset;


        for (disk_offset=disk_offset;
             (disk_offset+REQUIRED_MATCHES) < SKIP_AMOUNT && !synced;
             disk_offset++) {

            fill_buffer(st, pkts, REQUIRED_MATCHES, packet_get_next_raw);

            for (st->search_limit = 0;
                 (st->search_limit + REQUIRED_MATCHES) < SKIP_AMOUNT && !synced;
                 st->search_limit++)
            {
                int i;
                int matches_found = 0;
                fill_buffer(st, old_pkts, REQUIRED_MATCHES, buffer_get_packet);

                // Check to see if our run matches up
                for (i=0; i<REQUIRED_MATCHES; i++) {
                    int dat = pkts[i].data.nand_cycle.data;
                    int old_dat = old_pkts[i].data.nand_cycle.data;
                    int ctrl = pkts[i].data.nand_cycle.control;
                    int old_ctrl = old_pkts[i].data.nand_cycle.control;

                    if (dat == old_dat && ctrl == old_ctrl)
                        matches_found++;
                }
                
                // If enough packets match, we're synced
                if (matches_found >= REQUIRED_MATCHES-1) {
                    st->last_sec_dif = st->sec_dif;
                    st->last_nsec_dif = st->nsec_dif;
                    st->sec_dif =
                        -(pkts[REQUIRED_MATCHES/2].header.sec-old_pkts[REQUIRED_MATCHES/2].header.sec);
                    st->nsec_dif =
                        -(pkts[REQUIRED_MATCHES/2].header.nsec-old_pkts[REQUIRED_MATCHES/2].header.nsec);
                    if (st->nsec_dif > 1000000000L) {
                        st->nsec_dif -= 1000000000L;
                        st->sec_dif++;
                    }
                    else if (st->nsec_dif < 0) {
                        st->nsec_dif += 1000000000L;
                        st->sec_dif--;
                    }
                    synced=1;
                    buffer_unget_packet(st, old_pkts);
                }
                else {
                    empty_buffer(st, old_pkts, REQUIRED_MATCHES, buffer_unget_packet);
                    buffer_get_packet(st, old_pkts);
                }
            }

            if (!synced) {
                empty_buffer(st, pkts, REQUIRED_MATCHES, packet_unget);
                empty_buffer(st, old_pkts, REQUIRED_MATCHES,
                        buffer_unget_packet);
                packet_get_next_raw(st, pkts);
            }
        }
        if (!synced)
            printf("Couldn't join\n");

        // Now we're synced, just ignore the rest of the matched-buffer
        // packets.  This is because if they're in the buffer, they've
        // already been written out.
        int tries = 0;
        while ((st->buffer_offset+st->search_limit)%SKIP_AMOUNT != buffer_start-1) {
            struct pkt old_pkt;
            int dat, old_dat, ctrl, old_ctrl;
            buffer_get_packet(st, &old_pkt);
            packet_get_next_raw(st, &pkt);

            dat = pkt.data.nand_cycle.data;
            old_dat = old_pkt.data.nand_cycle.data;
            ctrl = pkt.data.nand_cycle.control;
            old_ctrl = old_pkt.data.nand_cycle.control;
            
            tries++;
            if ((dat != old_dat) || (ctrl != old_ctrl)) {
                printf("Join anomaly after %d tries: %d/%d and %d/%d\n",
                        tries, old_dat, dat, old_ctrl, ctrl);
            }
        }
        st->buffer_offset = -1;
        st->search_limit = 0;
    }

    // Done now, copy data
    while ((ret = packet_get_next_raw(st, &pkt)) == 0) {
        if (!is_nand(st, &pkt)) {
            packet_unget(st, &pkt);
            jstate_set(st, ST_SEARCHING);
            break;
        }

        if (st->nsec_dif > 0) {
            pkt.header.nsec += st->nsec_dif;
            if (pkt.header.nsec > 1000000000L) {
                pkt.header.nsec -= 1000000000L;
                pkt.header.sec++;
            }
            pkt.header.sec += st->sec_dif;
        }
        else {
            pkt.header.nsec -= st->nsec_dif;
            if (pkt.header.nsec <= 0) {
                pkt.header.nsec += 1000000000L;
                pkt.header.sec--;
            }
            pkt.header.sec -= st->sec_dif;
        }
        packet_write(st, &pkt);
        buffer_put_packet(st, &pkt);
    }

    return ret;
}

int main(int argc, char **argv) {
    struct state state;
    int ret;

    memset(&state, 0, sizeof(state));

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [in_filename] [out_filename]\n", argv[0]);
        return 1;
    }

    ret = open_files(&state, argv[1], argv[2]);
    if (ret)
        return ret;

    jstate_init(&state);
    while (jstate_state(&state) != ST_DONE && !ret)
        ret = jstate_run(&state);
    printf("State machine finished with result: %d\n", ret);

    return 0;
}

