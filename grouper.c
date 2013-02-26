#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include "packet-struct.h"
#include "groups-struct.h"
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


static int grp_write_id(struct state *st, struct pkt *pkt) {
    struct grp_nand_id grp;
    int byte;

    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_ID);

    // Grab the "address" byte.
    packet_get_next(st, pkt);
    if (!nand_ale(pkt->data.nand_cycle.control)
     || !nand_we(pkt->data.nand_cycle.control))
        fprintf(stderr, "Warning: ALE/WE not set for 'Read ID'\n");
    grp.addr = pkt->data.nand_cycle.data;

    // Read the actual ID
    for (byte=0; byte<sizeof(grp.id); byte++) {
        packet_get_next(st, pkt);
        if (nand_we(pkt->data.nand_cycle.control)
         || !nand_re(pkt->data.nand_cycle.control))
            fprintf(stderr, "Warning: RE not set for 'Read ID'\n");
        grp.id[byte] = pkt->data.nand_cycle.data;
    }

    grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}

static int grp_write_sandisk_set(struct state *st, struct pkt *pkt) {
    struct grp_nand_unk_sandisk_code grp;
    struct pkt second_pkt;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_SANDISK_VENDOR_START);

    // Make sure the subsequent packet is 0xc5
    packet_get_next(st, &second_pkt);
    if (!nand_cle(second_pkt.data.nand_cycle.control)
     || second_pkt.data.nand_cycle.data != 0xc5) {
        fprintf(stderr, "Not a Sandisk packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        return 0;
    }

    grp_fill_end(&grp, second_pkt.header.sec, second_pkt.header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}

static int grp_write_sandisk_param(struct state *st, struct pkt *pkt) {
    struct grp_nand_unk_sandisk_param grp;
    struct pkt second_pkt, third_pkt;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_SANDISK_VENDOR_PARAM);

    // Make sure the subsequent packet is an address
    packet_get_next(st, &second_pkt);
    if (!nand_ale(second_pkt.data.nand_cycle.control)
     && !nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk param packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        return 0;
    }

    packet_get_next(st, &third_pkt);
    if (nand_ale(third_pkt.data.nand_cycle.control)
     || nand_cle(third_pkt.data.nand_cycle.control)
     || nand_re(third_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk param packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        grp_write_nand_unk(st, &third_pkt);
        return 0;
    }

    grp.addr = second_pkt.data.nand_cycle.data;
    grp.data = third_pkt.data.nand_cycle.data;

    grp_fill_end(&grp, third_pkt.header.sec, third_pkt.header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_sandisk_charge1(struct state *st, struct pkt *pkt) {
    struct grp_nand_sandisk_charge1 grp;
    struct pkt second_pkt, third_pkt, fourth_pkt;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_SANDISK_CHARGE1);

    // Make sure the subsequent packet is an address
    packet_get_next(st, &second_pkt);
    if (!nand_ale(second_pkt.data.nand_cycle.control)
     || nand_cle(second_pkt.data.nand_cycle.control)
     || !nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge(?) packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        return 0;
    }

    packet_get_next(st, &third_pkt);
    if (!nand_ale(third_pkt.data.nand_cycle.control)
     || nand_cle(third_pkt.data.nand_cycle.control)
     || !nand_we(third_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge(?) packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        grp_write_nand_unk(st, &third_pkt);
        return 0;
    }

    packet_get_next(st, &fourth_pkt);
    if (!nand_ale(fourth_pkt.data.nand_cycle.control)
     || nand_cle(fourth_pkt.data.nand_cycle.control)
     || !nand_we(fourth_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge(?) packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        grp_write_nand_unk(st, &third_pkt);
        grp_write_nand_unk(st, &fourth_pkt);
        return 0;
    }

    grp.addr[0] = second_pkt.data.nand_cycle.data;
    grp.addr[1] = third_pkt.data.nand_cycle.data;
    grp.addr[2] = fourth_pkt.data.nand_cycle.data;

    grp_fill_end(&grp, fourth_pkt.header.sec, fourth_pkt.header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_sandisk_charge2(struct state *st, struct pkt *pkt) {
    struct grp_nand_sandisk_charge2 grp;
    struct pkt second_pkt, third_pkt, fourth_pkt;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_SANDISK_CHARGE1);

    // Make sure the subsequent packet is an address
    packet_get_next(st, &second_pkt);
    if (!nand_ale(second_pkt.data.nand_cycle.control)
     || nand_cle(second_pkt.data.nand_cycle.control)
     || !nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge2(?) packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        return 0;
    }

    packet_get_next(st, &third_pkt);
    if (!nand_ale(third_pkt.data.nand_cycle.control)
     || nand_cle(third_pkt.data.nand_cycle.control)
     || !nand_we(third_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge2(?) packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        grp_write_nand_unk(st, &third_pkt);
        return 0;
    }

    packet_get_next(st, &fourth_pkt);
    if (!nand_ale(fourth_pkt.data.nand_cycle.control)
     || nand_cle(fourth_pkt.data.nand_cycle.control)
     || !nand_we(fourth_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a Sandisk charge2(?) packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        grp_write_nand_unk(st, &third_pkt);
        grp_write_nand_unk(st, &fourth_pkt);
        return 0;
    }

    grp.addr[0] = second_pkt.data.nand_cycle.data;
    grp.addr[1] = third_pkt.data.nand_cycle.data;
    grp.addr[2] = fourth_pkt.data.nand_cycle.data;

    grp_fill_end(&grp, fourth_pkt.header.sec, fourth_pkt.header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_reset(struct state *st, struct pkt *pkt) {
    struct grp_nand_reset grp;
    struct pkt second_pkt;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_RESET);

    // Make sure the subsequent packet is 0xc5
    packet_get_next(st, &second_pkt);
    if (!nand_cle(second_pkt.data.nand_cycle.control)
     || second_pkt.data.nand_cycle.data != 0x00) {
        fprintf(stderr, "Not a reset packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        return 0;
    }

    grp_fill_end(&grp, second_pkt.header.sec, second_pkt.header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_cache1(struct state *st, struct pkt *pkt) {
    struct grp_nand_cache1 grp;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_CACHE1);
    grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_cache2(struct state *st, struct pkt *pkt) {
    struct grp_nand_cache2 grp;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_CACHE2);
    grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_cache3(struct state *st, struct pkt *pkt) {
    struct grp_nand_cache3 grp;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_CACHE3);
    grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_cache4(struct state *st, struct pkt *pkt) {
    struct grp_nand_cache4 grp;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_CACHE4);
    grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_status(struct state *st, struct pkt *pkt) {
    struct grp_nand_status grp;
    struct pkt second_pkt;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_STATUS);

    // Make sure the subsequent packet is a read of status
    packet_get_next(st, &second_pkt);
    if (nand_ale(second_pkt.data.nand_cycle.control)
     || nand_cle(second_pkt.data.nand_cycle.control)
     || nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a NAND status packet!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        return 0;
    }

    grp.status = second_pkt.data.nand_cycle.data;

    grp_fill_end(&grp, second_pkt.header.sec, second_pkt.header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_parameter_page(struct state *st, struct pkt *pkt) {
    struct grp_nand_parameter_read grp;
    struct pkt second_pkt;

    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_PARAMETER_READ);

    // Make sure the subsequent packet is a read of status
    packet_get_next(st, &second_pkt);
    if (!nand_ale(second_pkt.data.nand_cycle.control)
     || nand_cle(second_pkt.data.nand_cycle.control)
     || !nand_we(second_pkt.data.nand_cycle.control)) {
        fprintf(stderr, "Not a NAND parameter read!\n");
        grp_write_nand_unk(st, pkt);
        grp_write_nand_unk(st, &second_pkt);
        return 0;
    }

    grp.count = 0;
    grp.addr = second_pkt.data.nand_cycle.data;
    memset(grp.data, 0, sizeof(grp.data));

    grp.count = 0;

    grp_fill_end(&grp, second_pkt.header.sec, second_pkt.header.nsec);
    packet_get_next(st, pkt);
    while (nand_re(pkt->data.nand_cycle.control)) {
        grp.data[grp.count++] = pkt->data.nand_cycle.data;

        grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
        packet_get_next(st, pkt);
    }
    packet_unget(st, pkt);

    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_change_read_column(struct state *st, struct pkt *pkt) {
    struct grp_nand_change_read_column grp;
    struct pkt pkts[6];
    int counter;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_CHANGE_READ_COLUMN);


    for (counter=0; counter<5; counter++) {
        // Make sure the subsequent packet is an address
        packet_get_next(st, &pkts[counter]);
        if (!nand_ale(pkts[counter].data.nand_cycle.control)
         || nand_cle(pkts[counter].data.nand_cycle.control)
         || !nand_we(pkts[counter].data.nand_cycle.control)) {
            int countdown;
            fprintf(stderr, "Not a page_select packet\n");
            grp_write_nand_unk(st, pkt);
            for (countdown=0; countdown<=counter; countdown++)
                grp_write_nand_unk(st, &pkts[countdown]);
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
        grp_write_nand_unk(st, pkt);
        for (countdown=0; countdown<=counter; countdown++)
            grp_write_nand_unk(st, &pkts[countdown]);
        return 0;
    }

    grp.addr[0] = pkts[0].data.nand_cycle.data;
    grp.addr[1] = pkts[1].data.nand_cycle.data;
    grp.addr[2] = pkts[2].data.nand_cycle.data;
    grp.addr[3] = pkts[3].data.nand_cycle.data;
    grp.addr[4] = pkts[4].data.nand_cycle.data;
    grp.addr[5] = pkts[5].data.nand_cycle.data;

    grp.count = 0;
    grp_fill_end(&grp, pkts[6].header.sec, pkts[6].header.nsec);
    memcpy(grp.unknown, &pkt->data.nand_cycle.unknown, sizeof(grp.unknown));
    packet_get_next(st, pkt);
    while (nand_re(pkt->data.nand_cycle.control)) {
        grp.data[grp.count++] = pkt->data.nand_cycle.data;

        grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
        memcpy(grp.unknown, &pkt->data.nand_cycle.unknown, sizeof(grp.unknown));
        packet_get_next(st, pkt);
    }
    packet_unget(st, pkt);

    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


static int grp_write_nand_read(struct state *st, struct pkt *pkt) {
    struct grp_nand_read grp;
    struct pkt pkts[6];
    int counter;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_READ);


    for (counter=0; counter<5; counter++) {
        // Make sure the subsequent packet is an address
        packet_get_next(st, &pkts[counter]);
        if (!nand_ale(pkts[counter].data.nand_cycle.control)
         || nand_cle(pkts[counter].data.nand_cycle.control)
         || !nand_we(pkts[counter].data.nand_cycle.control)) {
            int countdown;
            fprintf(stderr, "Not a nand_read packet (counter %d)\n", counter);
            grp_write_nand_unk(st, pkt);
            for (countdown=0; countdown<=counter; countdown++)
                grp_write_nand_unk(st, &pkts[countdown]);
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
        grp_write_nand_unk(st, pkt);
        for (countdown=0; countdown<=counter; countdown++)
            grp_write_nand_unk(st, &pkts[countdown]);
        return 0;
    }

    grp.addr[0] = pkts[0].data.nand_cycle.data;
    grp.addr[1] = pkts[1].data.nand_cycle.data;
    grp.addr[2] = pkts[2].data.nand_cycle.data;
    grp.addr[3] = pkts[3].data.nand_cycle.data;
    grp.addr[4] = pkts[4].data.nand_cycle.data;
    grp.addr[5] = pkts[5].data.nand_cycle.data;

    grp.count = 0;
    grp_fill_end(&grp, pkts[6].header.sec, pkts[6].header.nsec);
    memcpy(grp.unknown, &pkt->data.nand_cycle.unknown, sizeof(grp.unknown));
    packet_get_next(st, pkt);
    while (nand_re(pkt->data.nand_cycle.control)) {
        grp.data[grp.count++] = pkt->data.nand_cycle.data;

        grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
        memcpy(grp.unknown, &pkt->data.nand_cycle.unknown, sizeof(grp.unknown));
        packet_get_next(st, pkt);
    }
    packet_unget(st, pkt);

    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}



static int write_nand_cmd(struct state *st, struct pkt *pkt) {
    struct pkt_nand_cycle *nand = &pkt->data.nand_cycle;

    // If it's not a command, we're lost
    if (!nand_cle(nand->control)) {
        fprintf(stderr, "We're lost in NAND-land.  ");
        nand_print(st, nand->data, nand->control);
        grp_write_nand_unk(st, pkt);
        return 0;
    }

    // "Get ID" command
    if (nand->data == 0x90) {
        return grp_write_id(st, pkt);
    }
    else if (nand->data == 0x5c) {
        grp_write_sandisk_set(st, pkt);
    }
    else if (nand->data == 0xff) {
        grp_write_nand_reset(st, pkt);
    }
    else if (nand->data == 0x55) {
        grp_write_sandisk_param(st, pkt);
    }
    else if (nand->data == 0x70) {
        grp_write_nand_status(st, pkt);
    }
    else if (nand->data == 0xec) {
        grp_write_nand_parameter_page(st, pkt);
    }
    else if (nand->data == 0x60) {
        grp_write_sandisk_charge2(st, pkt);
    }
    else if (nand->data == 0x65) {
        grp_write_sandisk_charge1(st, pkt);
    }
    else if (nand->data == 0x05) {
        grp_write_nand_change_read_column(st, pkt);
    }
    else if (nand->data == 0x00) {
        grp_write_nand_read(st, pkt);
    }
    else if (nand->data == 0x30) {
        grp_write_nand_cache1(st, pkt);
    }
    else if (nand->data == 0xa2) {
        grp_write_nand_cache2(st, pkt);
    }
    else if (nand->data == 0x69) {
        grp_write_nand_cache3(st, pkt);
    }
    else if (nand->data == 0xfd) {
        grp_write_nand_cache4(st, pkt);
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

void *grp_take(struct state *st, int type) {
    int i;
    for (i=0; i<(sizeof(st->groups)/sizeof(st->groups[0])); i++) {
        if (st->groups[i] && st->groups[i]->type == type) {
            void *val = st->groups[i];
            st->groups[i] = NULL;
            return val;
        }
    }
    return NULL;
}

int grp_put(struct state *st, void *v) {
    struct grp_header *val = v;
    int i;
    for (i=0; i<(sizeof(st->groups)/sizeof(st->groups[0])); i++) {
        if (!st->groups[i]) {
            st->groups[i] = val;
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
            grp_write_hello(st, &pkt);
        }

        else if (pkt.header.type == PACKET_RESET) {
            grp_write_reset(st, &pkt);
        }

        else if (pkt.header.type == PACKET_NAND_CYCLE) {
            write_nand_cmd(st, &pkt);
        }

        else if (pkt.header.type == PACKET_COMMAND) {
            if (pkt.data.command.start_stop == CMD_STOP) {
                struct grp_net_cmd *net = grp_take(st, GRP_NET_CMD);
                if (!net) {
                    struct grp_net_cmd grp;
                    fprintf(stderr, "NET_CMD end without begin\n");
                    grp_fill_header(&grp, pkt.header.sec, pkt.header.nsec,
                                    sizeof(grp), GRP_NET_CMD);
                    grp.cmd[0] = pkt.data.command.cmd[0];
                    grp.cmd[1] = pkt.data.command.cmd[1];
                    grp.arg = pkt.data.command.arg;
                    grp_fill_end(&grp, pkt.header.sec, pkt.header.nsec);
                    write(st->out_fd, &grp, sizeof(grp));
                }
                else {
                    grp_fill_end(net, pkt.header.sec, pkt.header.nsec);
                    write(st->out_fd, net, sizeof(*net));
                    free(net);
                }
            }
            else {
                struct grp_net_cmd *net = grp_take(st, GRP_NET_CMD);
                if (net) {
                    fprintf(stderr, "Multiple NET_CMDs going at once\n");
                    free(net);
                }

                net = malloc(sizeof(struct grp_net_cmd));
                grp_fill_header(net, pkt.header.sec, pkt.header.nsec,
                                sizeof(*net), GRP_NET_CMD);
                net->cmd[0] = pkt.data.command.cmd[0];
                net->cmd[1] = pkt.data.command.cmd[1];
                net->arg = pkt.data.command.arg;
                grp_put(st, net);
            }
        }

        else if (pkt.header.type == PACKET_BUFFER_DRAIN) {
            if (pkt.data.buffer_drain.start_stop == PKT_BUFFER_DRAIN_STOP) {
                struct grp_buffer_drain *grp = grp_take(st, GRP_BUFFER_DRAIN);
                if (!grp) {
                    struct grp_buffer_drain grp;
                    fprintf(stderr, "BUFFER_DRAIN end without begin\n");
                    grp_fill_header(&grp, pkt.header.sec, pkt.header.nsec,
                                    sizeof(grp), GRP_BUFFER_DRAIN);
                    grp_fill_end(&grp, pkt.header.sec, pkt.header.nsec);
                    write(st->out_fd, &grp, sizeof(grp));
                }
                else {
                    grp_fill_end(grp, pkt.header.sec, pkt.header.nsec);
                    write(st->out_fd, grp, sizeof(*grp));
                    free(grp);
                }
            }
            else {
                struct grp_buffer_drain *grp = grp_take(st, GRP_BUFFER_DRAIN);
                if (grp) {
                    fprintf(stderr, "Multiple BUFFER_DRAINs going at once\n");
                    free(grp);
                }

                grp = malloc(sizeof(struct grp_buffer_drain));
                grp_fill_header(grp, pkt.header.sec, pkt.header.nsec,
                                sizeof(*grp), GRP_BUFFER_DRAIN);
                grp_put(st, grp);
            }
        }

        else if (pkt.header.type == PACKET_SD_CMD_ARG) {
            struct grp_sd_cmd *grp = grp_take(st, GRP_SD_CMD);
            struct pkt_sd_cmd_arg *sd = &pkt.data.sd_cmd_arg;
            if (!grp) {
                grp = malloc(sizeof(struct grp_sd_cmd));
                memset(grp, 0, sizeof(*grp));
                grp_fill_header(grp, pkt.header.sec, pkt.header.nsec,
                                sizeof(*grp), GRP_SD_CMD);
            }

            // Ignore args for CMD55
            if ((grp->num_args || sd->reg>0) && grp->cmd != 0x55) {
                grp->args[grp->num_args++] = sd->val;
            }

            // Register 0 implies this is a CMD.
            else if (sd->reg == 0) {
                if (grp->cmd == 0x55)
                    grp->cmd = 0x80 | (0x3f & sd->val);
                else
                    grp->cmd = 0x3f & sd->val;
            }
            grp_put(st, grp);
        }
        else if (pkt.header.type == PACKET_SD_RESPONSE) {
            struct grp_sd_cmd *grp = grp_take(st, GRP_SD_CMD);
            // Ignore CMD17, as we'll pick it up on the PACKET_SD_DATA packet
            if (grp->cmd == 17) {
                grp_put(st, grp);
            }
            else {
                struct pkt_sd_response *sd = &pkt.data.response;
                if (!grp) {
                    fprintf(stderr, "Couldn't find old GRP_SD_CMD in SD_RESPONSE\n");
                    continue;
                }

                grp->result[grp->num_results++] = sd->byte;

                grp_fill_end(grp, pkt.header.sec, pkt.header.nsec);
                write(st->out_fd, grp, sizeof(*grp));
                free(grp);
            }
        }

        else if (pkt.header.type == PACKET_SD_DATA) {
            struct grp_sd_cmd *grp = grp_take(st, GRP_SD_CMD);
            struct pkt_sd_data *sd = &pkt.data.sd_data;
            int offset;
            if (!grp) {
                fprintf(stderr, "Couldn't find old SD_GRP_CMD in SD_DATA\n");
                continue;
            }

            for (offset=0; offset<sizeof(sd->data); offset++)
                grp->result[grp->num_results++] = sd->data[offset];

            grp_fill_end(grp, pkt.header.sec, pkt.header.nsec);
            write(st->out_fd, grp, sizeof(*grp));
            free(grp);
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

