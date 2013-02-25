#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include "packet-struct.h"
#include "state.h"

int packet_get_next(struct state *st, struct pkt *pkt) {
    int ret;

    ret = read(st->fd, &pkt->header, sizeof(pkt->header));
    if (ret < 0)
        return -1;

    if (ret == 0)
        return -1;

    ret = read(st->fd, &pkt->data, ntohs(pkt->header.size)-sizeof(pkt->header));
    if (ret < 0)
        return -1;

    if (ret == 0)
        return -1;

    return 0;
}
