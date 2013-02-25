#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include "packet-struct.h"
#include "state.h"

#define SKIP_AMOUNT 25

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
int packet_buffer_offset = 0;

enum prog_state {
    ST_DRAINING,
    ST_RUNNING,
    ST_STARTING,
    ST_JOINING,
    ST_DONE,
    ST_OVERFLOWED,
};

static int print_hex(uint8_t *block, int count) {
        int offset;
        int byte;
        for (offset=0; offset<count; offset+=16) {
                printf("%08x ", offset);
                for (byte=0; byte<16; byte++) {
                        if (byte == 8)
                                printf(" ");
                        printf(" %02x", block[offset+byte]&0xff);
                }

                printf("  |");
                for (byte=0; byte<16; byte++)
                        printf("%c", isprint(block[offset+byte])?block[offset+byte]:'.');
                printf("|\n");
        }
        return 0;
}

int main(int argc, char **argv) {
    struct state state;
    struct pkt pkt;

    memset(&state, 0, sizeof(state));

    if (argc != 2) {
        fprintf(stderr, "Usage: %s [in_filename]\n", argv[0]);
        return 1;
    }

    state.fd = open(argv[1], O_RDONLY);
    if (state.fd == -1) {
        perror("Unable to open input file");
        return 2;
    }

    state.is_logging = 0;
    state.st = ST_RUNNING;
    while (-1 != packet_get_next(&state, &pkt)) {
        if (pkt.header.type == PACKET_NAND_CYCLE) {
            nand_print(&state,
		nand_unscramble_byte(pkt.data.nand_cycle.data),
		pkt.data.nand_cycle.control);

            if (state.st == ST_JOINING) {
                if (state.skip_counter < SKIP_AMOUNT) {
                    printf("Old: %02x %02x   New: %02x %02x\n",
                            pkt.data.nand_cycle.data&0xff,
                            pkt.data.nand_cycle.control&0xff,
                            packet_buffer[packet_buffer_offset].data.nand_cycle.data&0xff,
                            packet_buffer[packet_buffer_offset].data.nand_cycle.control&0xff);
                    state.skip_counter++;
                }
            }
            memcpy(&packet_buffer[packet_buffer_offset], &pkt, sizeof(pkt));
            packet_buffer_offset++;
            packet_buffer_offset %= SKIP_AMOUNT;
        }
	else if (pkt.header.type == PACKET_SD_DATA) {
		print_hex(pkt.data.sd_data.data, 512);
	}
		
        else {
            printf("Packet: %s\n", types[pkt.header.type]);
        }

        if (state.is_logging) {
            write(state.out_fd, &pkt, sizeof(pkt));
        }
    }

    return 0;
}
