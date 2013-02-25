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
        return -2;
    pkt->header.sec = ntohl(pkt->header.sec);
    pkt->header.nsec = ntohl(pkt->header.nsec);
    pkt->header.size = ntohs(pkt->header.size);

    ret = read(st->fd, &pkt->data, pkt->header.size-sizeof(pkt->header));
    if (ret < 0)
        return -1;

    if (ret == 0)
        return -2;

    return 0;
}

int packet_unget(struct state *st, struct pkt *pkt) {
    return lseek(st->fd, -pkt->header.size, SEEK_CUR);
}

int packet_write(struct state *st, struct pkt *pkt) {
    struct pkt cp;
    memcpy(&cp, pkt, sizeof(cp));
    cp.header.sec = htonl(pkt->header.sec);
    cp.header.nsec = htonl(pkt->header.nsec);
    cp.header.size = htons(pkt->header.size);

    return write(st->out_fd, &cp, ntohs(cp.header.size));
}
