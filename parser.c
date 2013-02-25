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

enum prog_state {
    ST_DRAINING,
    ST_RUNNING,
    ST_STARTING,
    ST_JOINING,
    ST_DONE,
    ST_OVERFLOWED,
};

/* Pulls a packet out of the buffer.
 * It pulls it out of the given offset.
 */
static int buffer_get_packet(struct state *st, struct pkt *pkt) {
    memcpy(pkt, &packet_buffer[(st->buffer_offset+st->search_limit)%SKIP_AMOUNT], sizeof(*pkt));
    return 0;
}

int main(int argc, char **argv) {
    struct state state;
    struct pkt pkt;

    memset(&state, 0, sizeof(state));

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [in_filename] [out_filename]\n", argv[0]);
        return 1;
    }

    state.fd = open(argv[1], O_RDONLY);
    if (state.fd == -1) {
        perror("Unable to open input file");
        return 2;
    }

    state.out_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (state.out_fd == -1) {
        perror("Unable to open output file");
        return 3;
    }

    state.is_logging = 0;
    state.st = ST_RUNNING;
    while (-1 != packet_get_next(&state, &pkt)) {
        if (pkt.header.type == PACKET_ERROR) {
            if (pkt.data.error.subsystem == SUBSYS_FPGA
                    && pkt.data.error.code == FPGA_ERR_OVERFLOW) {
                state.st = ST_OVERFLOWED;
            }
            else {
                printf("Packet: %s - %d.%d.%d (%s)\n", types[pkt.header.type],
                    pkt.data.error.subsystem,
                    pkt.data.error.code,
                    pkt.data.error.arg,
                    pkt.data.error.message);
            }
        }
        else if (pkt.header.type == PACKET_BUFFER_DRAIN) {
//            printf("Packet: %s - %s\n", types[pkt.header.type],
//                    pkt.data.buffer_drain.start_stop==1?"Start":"Stop");
            if (pkt.data.buffer_drain.start_stop == PKT_BUFFER_DRAIN_STOP) {
                if (state.st == ST_OVERFLOWED) {
                    state.st = ST_JOINING;
                    state.skip_counter = 0;
                    state.search_limit = 0;
                    state.sec_dif = 0;
                    state.nsec_dif = 0;
                }
                else {
                    state.st = ST_RUNNING;
                }
            }

            else if (pkt.data.buffer_drain.start_stop == PKT_BUFFER_DRAIN_START) {
                if (state.st == ST_JOINING) {
//                    printf("Beginning join process...\n");
                }
                else {
//                    printf("Normal drain\n");
                    state.st = ST_DRAINING;
                }
            }
        }
        else if (pkt.header.type == PACKET_NAND_CYCLE) {

            if (state.st == ST_JOINING) {
                if (state.skip_counter+state.search_limit < SKIP_AMOUNT) {
                    struct pkt old_pkt;
                    buffer_get_packet(&state, &old_pkt);
                    while (pkt.data.nand_cycle.data != old_pkt.data.nand_cycle.data
                        && state.search_limit < SEARCH_LIMIT)
                    {
                        state.search_limit++;
                        buffer_get_packet(&state, &old_pkt);
                    }

                    if (old_pkt.data.nand_cycle.data != pkt.data.nand_cycle.data) {
                        state.search_limit = 0;
                        buffer_get_packet(&state, &old_pkt);
                        printf("Byte %d -- New: %02x %02x   Old: %02x %02x\n",
                            state.skip_counter,
                            nand_unscramble_byte(pkt.data.nand_cycle.data)&0xff,
                            pkt.data.nand_cycle.control&0xff,
                            nand_unscramble_byte(old_pkt.data.nand_cycle.data)&0xff,
                            old_pkt.data.nand_cycle.control&0xff);
                        // Back up by one and try again on the next loop around
                        state.buffer_offset--;
                        state.search_limit = 0;
			continue;
                    }
                    else {
                        state.sec_dif = old_pkt.header.sec - pkt.header.sec;
                        state.nsec_dif = old_pkt.header.nsec - pkt.header.nsec;
                    }
                    state.skip_counter++;
                    pkt.header.sec += state.sec_dif;
                    pkt.header.nsec += state.nsec_dif;
                }
                else {
                    write(state.out_fd, &pkt, ntohs(pkt.header.size));
                    pkt.header.sec += state.sec_dif;
                    pkt.header.nsec += state.nsec_dif;
                }
            }
            else
                write(state.out_fd, &pkt, ntohs(pkt.header.size));
            nand_print(&state, pkt.data.nand_cycle.data, pkt.data.nand_cycle.control);
            memcpy(&packet_buffer[state.buffer_offset], &pkt, sizeof(pkt));
            state.buffer_offset++;
            state.buffer_offset %= SKIP_AMOUNT;

        }

        else if (pkt.header.type == PACKET_COMMAND) {
            char *dir = ">>>";
            if (pkt.data.command.start_stop == 2) {
                dir = "<<<";
                if (pkt.data.command.cmd[0] == 'i' && pkt.data.command.cmd[1] == 'b')
                    printf("%s %c%c %d\n", dir,
                            pkt.data.command.cmd[0],
                            pkt.data.command.cmd[1],
                            ntohl(pkt.data.command.arg));
            }
            if (state.commands++ > 50 && state.st != ST_JOINING && state.st
                    != ST_OVERFLOWED)
                state.is_logging = 1;
        }
        else {
//            printf("Packet: %s\n", types[pkt.header.type]);
        }

    }

    return 0;
}
