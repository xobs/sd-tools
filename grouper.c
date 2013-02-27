#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "packet-struct.h"
#include "event-struct.h"
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

enum prog_state {
    ST_UNINITIALIZED,
    ST_SCANNING,
    ST_GROUPING,
    ST_DONE,
};


static int st_uninitialized(struct state *st);
static int st_scanning(struct state *st);
static int st_grouping(struct state *st);
static int st_done(struct state *st);

static int (*st_funcs[])(struct state *st) = {
    [ST_UNINITIALIZED]  = st_uninitialized,
    [ST_SCANNING]       = st_scanning,
    [ST_GROUPING]       = st_grouping,
    [ST_DONE]           = st_done,
};


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


static int evt_write_id(struct state *st, struct pkt *pkt) {
    struct evt_nand_id evt;

    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_ID);

    // Grab the "address" byte.
    packet_get_next(st, pkt);
    if (!nand_ale(pkt->data.nand_cycle.control)
     || !nand_we(pkt->data.nand_cycle.control))
        fprintf(stderr, "Warning: ALE/WE not set for 'Read ID'\n");
    evt.addr = pkt->data.nand_cycle.data;

    // Read the actual ID
    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    packet_get_next(st, pkt);
    for (evt.size=0;
         evt.size<sizeof(evt.id) && nand_re(pkt->data.nand_cycle.control);
         evt.size++) {
        evt.id[evt.size] = pkt->data.nand_cycle.data;
        evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
        packet_get_next(st, pkt);
    }

    if (!nand_re(pkt->data.nand_cycle.control))
        packet_unget(st, pkt);

    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}

static int evt_write_sandisk_set(struct state *st, struct pkt *pkt) {
    struct evt_nand_unk_sandisk_code evt;
    struct pkt second_pkt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_SANDISK_VENDOR_START);

    // Make sure the subsequent packet is 0xc5
    packet_get_next(st, &second_pkt);
    if (!nand_cle(second_pkt.data.nand_cycle.control)
     || second_pkt.data.nand_cycle.data != 0xc5) {
        fprintf(stderr, "Not a Sandisk packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        return 0;
    }

    evt_fill_end(&evt, second_pkt.header.sec, second_pkt.header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}

static int evt_write_sandisk_param(struct state *st, struct pkt *pkt) {
    struct evt_nand_unk_sandisk_param evt;
    struct pkt second_pkt, third_pkt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_SANDISK_VENDOR_PARAM);

    // Make sure the subsequent packet is an address
    packet_get_next(st, &second_pkt);
    if (!nand_ale(second_pkt.data.nand_cycle.control)
     && !nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk param packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        return 0;
    }

    packet_get_next(st, &third_pkt);
    if (nand_ale(third_pkt.data.nand_cycle.control)
     || nand_cle(third_pkt.data.nand_cycle.control)
     || nand_re(third_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk param packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        evt_write_nand_unk(st, &third_pkt);
        return 0;
    }

    evt.addr = second_pkt.data.nand_cycle.data;
    evt.data = third_pkt.data.nand_cycle.data;

    evt_fill_end(&evt, third_pkt.header.sec, third_pkt.header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_sandisk_charge1(struct state *st, struct pkt *pkt) {
    struct evt_nand_sandisk_charge1 evt;
    struct pkt second_pkt, third_pkt, fourth_pkt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_SANDISK_CHARGE1);

    // Make sure the subsequent packet is an address
    packet_get_next(st, &second_pkt);
    if (!nand_ale(second_pkt.data.nand_cycle.control)
     || nand_cle(second_pkt.data.nand_cycle.control)
     || !nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge(?) packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        return 0;
    }

    packet_get_next(st, &third_pkt);
    if (!nand_ale(third_pkt.data.nand_cycle.control)
     || nand_cle(third_pkt.data.nand_cycle.control)
     || !nand_we(third_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge(?) packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        evt_write_nand_unk(st, &third_pkt);
        return 0;
    }

    packet_get_next(st, &fourth_pkt);
    if (!nand_ale(fourth_pkt.data.nand_cycle.control)
     || nand_cle(fourth_pkt.data.nand_cycle.control)
     || !nand_we(fourth_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge(?) packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        evt_write_nand_unk(st, &third_pkt);
        evt_write_nand_unk(st, &fourth_pkt);
        return 0;
    }

    evt.addr[0] = second_pkt.data.nand_cycle.data;
    evt.addr[1] = third_pkt.data.nand_cycle.data;
    evt.addr[2] = fourth_pkt.data.nand_cycle.data;

    evt_fill_end(&evt, fourth_pkt.header.sec, fourth_pkt.header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_sandisk_charge2(struct state *st, struct pkt *pkt) {
    struct evt_nand_sandisk_charge2 evt;
    struct pkt second_pkt, third_pkt, fourth_pkt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_SANDISK_CHARGE1);

    // Make sure the subsequent packet is an address
    packet_get_next(st, &second_pkt);
    if (!nand_ale(second_pkt.data.nand_cycle.control)
     || nand_cle(second_pkt.data.nand_cycle.control)
     || !nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge2(?) packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        return 0;
    }

    packet_get_next(st, &third_pkt);
    if (!nand_ale(third_pkt.data.nand_cycle.control)
     || nand_cle(third_pkt.data.nand_cycle.control)
     || !nand_we(third_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge2(?) packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        evt_write_nand_unk(st, &third_pkt);
        return 0;
    }

    packet_get_next(st, &fourth_pkt);
    if (!nand_ale(fourth_pkt.data.nand_cycle.control)
     || nand_cle(fourth_pkt.data.nand_cycle.control)
     || !nand_we(fourth_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge2(?) packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        evt_write_nand_unk(st, &third_pkt);
        evt_write_nand_unk(st, &fourth_pkt);
        return 0;
    }

    evt.addr[0] = second_pkt.data.nand_cycle.data;
    evt.addr[1] = third_pkt.data.nand_cycle.data;
    evt.addr[2] = fourth_pkt.data.nand_cycle.data;

    evt_fill_end(&evt, fourth_pkt.header.sec, fourth_pkt.header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_reset(struct state *st, struct pkt *pkt) {
    struct evt_nand_reset evt;
    struct pkt second_pkt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_RESET);

    // Make sure the subsequent packet is 0xc5
    packet_get_next(st, &second_pkt);
    if (!nand_cle(second_pkt.data.nand_cycle.control)
     || second_pkt.data.nand_cycle.data != 0x00) {
        fprintf(stderr, "Not a reset packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        return 0;
    }

    evt_fill_end(&evt, second_pkt.header.sec, second_pkt.header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_cache1(struct state *st, struct pkt *pkt) {
    struct evt_nand_cache1 evt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_CACHE1);
    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_cache2(struct state *st, struct pkt *pkt) {
    struct evt_nand_cache2 evt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_CACHE2);
    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_cache3(struct state *st, struct pkt *pkt) {
    struct evt_nand_cache3 evt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_CACHE3);
    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_cache4(struct state *st, struct pkt *pkt) {
    struct evt_nand_cache4 evt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_CACHE4);
    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_status(struct state *st, struct pkt *pkt) {
    struct evt_nand_status evt;
    struct pkt second_pkt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_STATUS);

    // Make sure the subsequent packet is a read of status
    packet_get_next(st, &second_pkt);
    if (nand_ale(second_pkt.data.nand_cycle.control)
     || nand_cle(second_pkt.data.nand_cycle.control)
     || nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a NAND status packet!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        return 0;
    }

    evt.status = second_pkt.data.nand_cycle.data;

    evt_fill_end(&evt, second_pkt.header.sec, second_pkt.header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_parameter_page(struct state *st, struct pkt *pkt) {
    struct evt_nand_parameter_read evt;
    struct pkt second_pkt;

    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_PARAMETER_READ);

    // Make sure the subsequent packet is a read of status
    packet_get_next(st, &second_pkt);
    if (!nand_ale(second_pkt.data.nand_cycle.control)
     || nand_cle(second_pkt.data.nand_cycle.control)
     || !nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a NAND parameter read!\n");
        evt_write_nand_unk(st, pkt);
        evt_write_nand_unk(st, &second_pkt);
        return 0;
    }

    evt.count = 0;
    evt.addr = second_pkt.data.nand_cycle.data;
    memset(evt.data, 0, sizeof(evt.data));

    evt.count = 0;

    evt_fill_end(&evt, second_pkt.header.sec, second_pkt.header.nsec);
    packet_get_next(st, pkt);
    while (nand_re(pkt->data.nand_cycle.control)) {
        evt.data[evt.count++] = pkt->data.nand_cycle.data;

        evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
        packet_get_next(st, pkt);
    }
    packet_unget(st, pkt);

    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_change_read_column(struct state *st, struct pkt *pkt) {
    struct evt_nand_change_read_column evt;
    struct pkt pkts[6];
    int counter;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_CHANGE_READ_COLUMN);


    for (counter=0; counter<5; counter++) {
        // Make sure the subsequent packet is an address
        packet_get_next(st, &pkts[counter]);
        if (!nand_ale(pkts[counter].data.nand_cycle.control)
         || nand_cle(pkts[counter].data.nand_cycle.control)
         || !nand_we(pkts[counter].data.nand_cycle.control)) {
            int countdown;
            fprintf(stderr, "Not a page_select packet\n");
            evt_write_nand_unk(st, pkt);
            for (countdown=0; countdown<=counter; countdown++)
                evt_write_nand_unk(st, &pkts[countdown]);
            return 0;
        }
    }

    // Next one should be a command, with type 0xe0
    packet_get_next(st, &pkts[counter]);
    if (nand_ale(pkts[counter].data.nand_cycle.control)
     || !nand_cle(pkts[counter].data.nand_cycle.control)
     || !nand_we(pkts[counter].data.nand_cycle.control)
     || pkts[counter].data.nand_cycle.data != 0xe0) {
        int countdown;
        fprintf(stderr, "Not a page_select packet (last packet wrong)\n");
        evt_write_nand_unk(st, pkt);
        for (countdown=0; countdown<=counter; countdown++)
            evt_write_nand_unk(st, &pkts[countdown]);
        return 0;
    }

    evt.addr[0] = pkts[0].data.nand_cycle.data;
    evt.addr[1] = pkts[1].data.nand_cycle.data;
    evt.addr[2] = pkts[2].data.nand_cycle.data;
    evt.addr[3] = pkts[3].data.nand_cycle.data;
    evt.addr[4] = pkts[4].data.nand_cycle.data;
    evt.addr[5] = pkts[5].data.nand_cycle.data;

    evt.count = 0;
    evt_fill_end(&evt, pkts[6].header.sec, pkts[6].header.nsec);
    memcpy(evt.unknown, &pkt->data.nand_cycle.unknown, sizeof(evt.unknown));
    packet_get_next(st, pkt);
    while (nand_re(pkt->data.nand_cycle.control)) {
        evt.data[evt.count++] = pkt->data.nand_cycle.data;

        evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
        memcpy(evt.unknown, &pkt->data.nand_cycle.unknown, sizeof(evt.unknown));
        packet_get_next(st, pkt);
    }
    packet_unget(st, pkt);

    evt.count = htonl(evt.count);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


static int evt_write_nand_read(struct state *st, struct pkt *pkt) {
    struct evt_nand_read evt;
    struct pkt pkts[6];
    int counter;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_READ);


    for (counter=0; counter<5; counter++) {
        // Make sure the subsequent packet is an address
        packet_get_next(st, &pkts[counter]);
        if (!nand_ale(pkts[counter].data.nand_cycle.control)
         || nand_cle(pkts[counter].data.nand_cycle.control)
         || !nand_we(pkts[counter].data.nand_cycle.control)) {
            int countdown;
            fprintf(stderr, "Not a nand_read packet (counter %d)\n", counter);
            evt_write_nand_unk(st, pkt);
            for (countdown=0; countdown<=counter; countdown++)
                evt_write_nand_unk(st, &pkts[countdown]);
            return 0;
        }
    }

    // Next one should be a command, with type 0xe0
    packet_get_next(st, &pkts[counter]);
    if (nand_ale(pkts[counter].data.nand_cycle.control)
     || !nand_cle(pkts[counter].data.nand_cycle.control)
     || !nand_we(pkts[counter].data.nand_cycle.control)
     || pkts[counter].data.nand_cycle.data != 0x30) {
        int countdown;
        fprintf(stderr, "Not a nand_read packet (last packet wrong)\n");
        evt_write_nand_unk(st, pkt);
        for (countdown=0; countdown<=counter; countdown++)
            evt_write_nand_unk(st, &pkts[countdown]);
        return 0;
    }

    evt.addr[0] = pkts[0].data.nand_cycle.data;
    evt.addr[1] = pkts[1].data.nand_cycle.data;
    evt.addr[2] = pkts[2].data.nand_cycle.data;
    evt.addr[3] = pkts[3].data.nand_cycle.data;
    evt.addr[4] = pkts[4].data.nand_cycle.data;
    evt.addr[5] = pkts[5].data.nand_cycle.data;

    evt.count = 0;
    evt_fill_end(&evt, pkts[6].header.sec, pkts[6].header.nsec);
    memcpy(evt.unknown, &pkt->data.nand_cycle.unknown, sizeof(evt.unknown));
    packet_get_next(st, pkt);
    while (nand_re(pkt->data.nand_cycle.control)) {
        evt.data[evt.count++] = pkt->data.nand_cycle.data;

        evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
        memcpy(evt.unknown, &pkt->data.nand_cycle.unknown, sizeof(evt.unknown));
        packet_get_next(st, pkt);
    }
    packet_unget(st, pkt);

    evt.count = htonl(evt.count);

    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}



static int write_nand_cmd(struct state *st, struct pkt *pkt) {
    struct pkt_nand_cycle *nand = &pkt->data.nand_cycle;

    // If it's not a command, we're lost
    if (!nand_cle(nand->control)) {
        fprintf(stderr, "We're lost in NAND-land.  ");
        nand_print(st, nand->data, nand->control);
        evt_write_nand_unk(st, pkt);
        return 0;
    }

    // "Get ID" command
    if (nand->data == 0x90) {
        return evt_write_id(st, pkt);
    }
    else if (nand->data == 0x5c) {
        evt_write_sandisk_set(st, pkt);
    }
    else if (nand->data == 0xff) {
        evt_write_nand_reset(st, pkt);
    }
    else if (nand->data == 0x55) {
        evt_write_sandisk_param(st, pkt);
    }
    else if (nand->data == 0x70) {
        evt_write_nand_status(st, pkt);
    }
    else if (nand->data == 0xec) {
        evt_write_nand_parameter_page(st, pkt);
    }
    else if (nand->data == 0x60) {
        evt_write_sandisk_charge2(st, pkt);
    }
    else if (nand->data == 0x65) {
        evt_write_sandisk_charge1(st, pkt);
    }
    else if (nand->data == 0x05) {
        evt_write_nand_change_read_column(st, pkt);
    }
    else if (nand->data == 0x00) {
        evt_write_nand_read(st, pkt);
    }
    else if (nand->data == 0x30) {
        evt_write_nand_cache1(st, pkt);
    }
    else if (nand->data == 0xa2) {
        evt_write_nand_cache2(st, pkt);
    }
    else if (nand->data == 0x69) {
        evt_write_nand_cache3(st, pkt);
    }
    else if (nand->data == 0xfd) {
        evt_write_nand_cache4(st, pkt);
    }
    else {
        fprintf(stderr, "Unknown NAND command.  ");
        nand_print(st, nand->data, nand->control);
    }
    return 0;
}


// Initialize the "joiner" state machine
static int gstate_init(struct state *st) {
    st->is_logging = 0;
    st->st = ST_SCANNING;
    st->last_run_offset = 0;
    st->join_buffer_capacity = 0;
    st->buffer_offset = -1;
    st->search_limit = 0;
    return 0;
}

static int gstate_state(struct state *st) {
    return st->st;
}

static int gstate_run(struct state *st) {
    return st_funcs[st->st](st);
}

void *evt_take(struct state *st, int type) {
    int i;
    for (i=0; i<(sizeof(st->events)/sizeof(st->events[0])); i++) {
        if (st->events[i] && st->events[i]->type == type) {
            void *val = st->events[i];
            st->events[i] = NULL;
            return val;
        }
    }
    return NULL;
}

int evt_put(struct state *st, void *v) {
    struct evt_header *val = v;
    int i;
    for (i=0; i<(sizeof(st->events)/sizeof(st->events[0])); i++) {
        if (!st->events[i]) {
            st->events[i] = val;
            return 0;
        }
    }
    return 1;
}



// Dummy state that should never be reached
static int st_uninitialized(struct state *st) {
    printf("state error: should not be in this state\n");
    return -1;
}

// Searching for either a NAND block or a sync point
static int st_scanning(struct state *st) {
    struct pkt pkt;
    int ret;
    while ((ret = packet_get_next(st, &pkt)) == 0) {

        if (pkt.header.type == PACKET_HELLO) {
            evt_write_hello(st, &pkt);
        }

        else if (pkt.header.type == PACKET_RESET) {
            evt_write_reset(st, &pkt);
        }

        else if (pkt.header.type == PACKET_NAND_CYCLE) {
            write_nand_cmd(st, &pkt);
        }

        else if (pkt.header.type == PACKET_COMMAND) {
            if (pkt.data.command.start_stop == CMD_STOP) {
                struct evt_net_cmd *net = evt_take(st, EVT_NET_CMD);
                if (!net) {
                    struct evt_net_cmd evt;
                    fprintf(stderr, "NET_CMD end without begin\n");
                    evt_fill_header(&evt, pkt.header.sec, pkt.header.nsec,
                                    sizeof(evt), EVT_NET_CMD);
                    evt.cmd[0] = pkt.data.command.cmd[0];
                    evt.cmd[1] = pkt.data.command.cmd[1];
                    evt.arg = pkt.data.command.arg;
                    evt_fill_end(&evt, pkt.header.sec, pkt.header.nsec);
                    evt.arg = htonl(evt.arg);
                    write(st->out_fd, &evt, sizeof(evt));
                }
                else {
                    evt_fill_end(net, pkt.header.sec, pkt.header.nsec);
                    net->arg = htonl(net->arg);
                    write(st->out_fd, net, sizeof(*net));
                    free(net);
                }
            }
            else {
                struct evt_net_cmd *net = evt_take(st, EVT_NET_CMD);
                if (net) {
                    fprintf(stderr, "Multiple NET_CMDs going at once\n");
                    free(net);
                }

                net = malloc(sizeof(struct evt_net_cmd));
                evt_fill_header(net, pkt.header.sec, pkt.header.nsec,
                                sizeof(*net), EVT_NET_CMD);
                net->cmd[0] = pkt.data.command.cmd[0];
                net->cmd[1] = pkt.data.command.cmd[1];
                net->arg = pkt.data.command.arg;
                evt_put(st, net);
            }
        }

        else if (pkt.header.type == PACKET_BUFFER_DRAIN) {
            if (pkt.data.buffer_drain.start_stop == PKT_BUFFER_DRAIN_STOP) {
                struct evt_buffer_drain *evt = evt_take(st, EVT_BUFFER_DRAIN);
                if (!evt) {
                    struct evt_buffer_drain evt;
                    fprintf(stderr, "BUFFER_DRAIN end without begin\n");
                    evt_fill_header(&evt, pkt.header.sec, pkt.header.nsec,
                                    sizeof(evt), EVT_BUFFER_DRAIN);
                    evt_fill_end(&evt, pkt.header.sec, pkt.header.nsec);
                    write(st->out_fd, &evt, sizeof(evt));
                }
                else {
                    evt_fill_end(evt, pkt.header.sec, pkt.header.nsec);
                    write(st->out_fd, evt, sizeof(*evt));
                    free(evt);
                }
            }
            else {
                struct evt_buffer_drain *evt = evt_take(st, EVT_BUFFER_DRAIN);
                if (evt) {
                    fprintf(stderr, "Multiple BUFFER_DRAINs going at once\n");
                    free(evt);
                }

                evt = malloc(sizeof(struct evt_buffer_drain));
                evt_fill_header(evt, pkt.header.sec, pkt.header.nsec,
                                sizeof(*evt), EVT_BUFFER_DRAIN);
                evt_put(st, evt);
            }
        }

        else if (pkt.header.type == PACKET_SD_CMD_ARG) {
            struct evt_sd_cmd *evt = evt_take(st, EVT_SD_CMD);
            struct pkt_sd_cmd_arg *sd = &pkt.data.sd_cmd_arg;
            if (!evt) {
                evt = malloc(sizeof(struct evt_sd_cmd));
                memset(evt, 0, sizeof(*evt));
                evt_fill_header(evt, pkt.header.sec, pkt.header.nsec,
                                sizeof(*evt), EVT_SD_CMD);
            }

            // Ignore args for CMD55
            if ((evt->num_args || sd->reg>0) && evt->cmd != 0x55) {
                evt->args[evt->num_args++] = sd->val;
            }

            // Register 0 implies this is a CMD.
            else if (sd->reg == 0) {
                if (evt->cmd == 0x55)
                    evt->cmd = 0x80 | (0x3f & sd->val);
                else
                    evt->cmd = 0x3f & sd->val;
            }
            evt_put(st, evt);
        }
        else if (pkt.header.type == PACKET_SD_RESPONSE) {
            struct evt_sd_cmd *evt = evt_take(st, EVT_SD_CMD);
            // Ignore CMD17, as we'll pick it up on the PACKET_SD_DATA packet
            if (evt->cmd == 17) {
                evt_put(st, evt);
            }
            else {
                struct pkt_sd_response *sd = &pkt.data.response;
                if (!evt) {
                    fprintf(stderr, "Couldn't find old EVT_SD_CMD in SD_RESPONSE\n");
                    continue;
                }

                evt->result[evt->num_results++] = sd->byte;
                evt->num_results = htonl(evt->num_results);
                evt->num_args = htonl(evt->num_args);

                evt_fill_end(evt, pkt.header.sec, pkt.header.nsec);
                write(st->out_fd, evt, sizeof(*evt));
                free(evt);
            }
        }

        else if (pkt.header.type == PACKET_SD_DATA) {
            struct evt_sd_cmd *evt = evt_take(st, EVT_SD_CMD);
            struct pkt_sd_data *sd = &pkt.data.sd_data;
            int offset;
            if (!evt) {
                fprintf(stderr, "Couldn't find old SD_EVT_CMD in SD_DATA\n");
                continue;
            }

            for (offset=0; offset<sizeof(sd->data); offset++)
                evt->result[evt->num_results++] = sd->data[offset];

            evt->num_results = htonl(evt->num_results);
            evt->num_args = htonl(evt->num_args);
            evt_fill_end(evt, pkt.header.sec, pkt.header.nsec);
            write(st->out_fd, evt, sizeof(*evt));
            free(evt);
        }

        else {
            printf("Unknown packet type: %s\n", types[pkt.header.type]);
        }
    }

    return ret;
}

static int st_grouping(struct state *st) {
    return 0;
}

static int st_done(struct state *st) {
    printf("Done.\n");
    exit(0);
    return 0;
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

    gstate_init(&state);
    while (gstate_state(&state) != ST_DONE && !ret)
        ret = gstate_run(&state);
    printf("State machine finished with result: %d\n", ret);

    return 0;
}

