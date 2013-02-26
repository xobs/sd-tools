#include <string.h>
#include <unistd.h>
#include "state.h"
#include "groups-struct.h"
#include "packet-struct.h"

int grp_fill_header(void *arg, uint32_t sec_start, uint32_t nsec_start,
                    uint32_t size, uint8_t type) {
    struct grp_header *hdr = arg;
    memset(hdr, 0, sizeof(*hdr));
    hdr->sec_start = sec_start;
    hdr->nsec_start = nsec_start;
    hdr->size = size;
    hdr->type = type;
    return 0;
}

int grp_fill_end(void *arg, uint32_t sec_end, uint32_t nsec_end) {
    struct grp_header *hdr = arg;
    hdr->sec_end = sec_end;
    hdr->nsec_end = nsec_end;
    return 0;
}


int grp_write_hello(struct state *st, struct pkt *pkt) {
    struct grp_hello grp;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_HELLO);
    grp.version = pkt->data.hello.version;
    grp.magic1 = GROUP_MAGIC_1;
    grp.magic2 = GROUP_MAGIC_2;
    grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}


int grp_write_reset(struct state *st, struct pkt *pkt) {
    struct grp_reset grp;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_RESET);
    grp.version = pkt->data.reset.version;
    grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}

int grp_write_nand_unk(struct state *st, struct pkt *pkt) {
    struct grp_nand_unk grp;
    grp_fill_header(&grp, pkt->header.sec, pkt->header.nsec,
                    sizeof(grp), GRP_NAND_UNKNOWN);
    grp.data = pkt->data.nand_cycle.data;
    grp.ctrl = pkt->data.nand_cycle.control;
    grp.unknown = pkt->data.nand_cycle.unknown;
    grp_fill_end(&grp, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &grp, sizeof(grp));
    return 0;
}
