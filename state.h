#ifndef __STATE_H__
#define __STATE_H__

#include <stdint.h>

struct pkt;

struct state {
    int fd;
    int out_fd;
    int st;
    uint32_t last_sec, last_nsec;
    int skip_counter;
    int is_logging;
    int commands;
    int search_limit;
    int buffer_offset;
    int sec_dif, nsec_dif;
};

int packet_get_next(struct state *st, struct pkt *pkt);
uint8_t nand_unscramble_byte(uint8_t byte);
int nand_print(struct state *st, uint8_t data, uint8_t ctrl);

#endif // __STATE_H__
