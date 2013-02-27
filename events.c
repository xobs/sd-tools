#include <string.h>
#include <unistd.h>
#include "state.h"
#include "packet-struct.h"
#include "event-struct.h"

int event_get_next(struct state *st, union evt *evt) {
    int ret;
    int bytes_to_read;

    ret = read(st->fd, &evt->header, sizeof(evt->header));
    if (ret < 0) {
        perror("Couldn't read header");
        return -1;
    }

    if (ret == 0) {
        perror("End of file for header");
        return -2;
    }
    evt->header.sec_start = ntohl(evt->header.sec_start);
    evt->header.nsec_start = ntohl(evt->header.nsec_start);
    evt->header.sec_end = ntohl(evt->header.sec_end);
    evt->header.nsec_end = ntohl(evt->header.nsec_end);
    evt->header.size = ntohl(evt->header.size);

    bytes_to_read = evt->header.size - sizeof(evt->header);
    ret = read(st->fd,
               ((char *)&(evt->header)) + sizeof(evt->header),
               bytes_to_read);

    if (ret < 0) {
        perror("Couldn't read");
        return -1;
    }

    if (ret == 0 && bytes_to_read > 0) {
        perror("End of file");
        return -2;
    }

    return 0;
}

int event_unget(struct state *st, union evt *evt) {
    return lseek(st->fd, -evt->header.size, SEEK_CUR);
}

int event_write(struct state *st, union evt *evt) {
    int ret;
    evt->header.sec_start = htonl(evt->header.sec_start);
    evt->header.nsec_start = htonl(evt->header.nsec_start);
    evt->header.sec_end = htonl(evt->header.sec_end);
    evt->header.nsec_end = htonl(evt->header.nsec_end);
    evt->header.size = htonl(evt->header.size);
    ret = write(st->out_fd, evt, ntohl(evt->header.size));

    evt->header.sec_start = ntohl(evt->header.sec_start);
    evt->header.nsec_start = ntohl(evt->header.nsec_start);
    evt->header.sec_end = ntohl(evt->header.sec_end);
    evt->header.nsec_end = ntohl(evt->header.nsec_end);
    evt->header.size = ntohl(evt->header.size);

    return ret;
}


int evt_fill_header(void *arg, uint32_t sec_start, uint32_t nsec_start,
                    uint32_t size, uint8_t type) {
    struct evt_header *hdr = arg;
    memset(hdr, 0, sizeof(*hdr));
    hdr->sec_start = htonl(sec_start);
    hdr->nsec_start = htonl(nsec_start);
    hdr->size = htonl(size);
    hdr->type = type;
    return 0;
}

int evt_fill_end(void *arg, uint32_t sec_end, uint32_t nsec_end) {
    struct evt_header *hdr = arg;
    hdr->sec_end = htonl(sec_end);
    hdr->nsec_end = htonl(nsec_end);
    return 0;
}


int evt_write_hello(struct state *st, struct pkt *pkt) {
    struct evt_hello evt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_HELLO);
    evt.version = pkt->data.hello.version;
    evt.magic1 = htonl(EVENT_MAGIC_1);
    evt.magic2 = htonl(EVENT_MAGIC_2);
    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}


int evt_write_reset(struct state *st, struct pkt *pkt) {
    struct evt_reset evt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_RESET);
    evt.version = pkt->data.reset.version;
    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}

int evt_write_nand_unk(struct state *st, struct pkt *pkt) {
    struct evt_nand_unk evt;
    evt_fill_header(&evt, pkt->header.sec, pkt->header.nsec,
                    sizeof(evt), EVT_NAND_UNKNOWN);
    evt.data = pkt->data.nand_cycle.data;
    evt.ctrl = pkt->data.nand_cycle.control;
    evt.unknown = pkt->data.nand_cycle.unknown;
    evt_fill_end(&evt, pkt->header.sec, pkt->header.nsec);
    write(st->out_fd, &evt, sizeof(evt));
    return 0;
}
