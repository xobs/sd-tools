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

struct state *g_st;

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

static uint32_t hdrs[16777216];
static int hdr_count;


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


int compare_event_addrs(const void *a1, const void *a2) {
    const uint32_t *o1 = a1;
    const uint32_t *o2 = a2;
    const union evt e1, e2;

    lseek(g_st->fd, *o1, SEEK_SET);
    event_get_next(g_st, &e1);

    lseek(g_st->fd, *o2, SEEK_SET);
    event_get_next(g_st, &e2);

    if (e1.header.sec_start < e2.header.sec_start)
        return -1;
    if (e1.header.sec_start > e2.header.sec_start)
        return 1;
    if (e1.header.nsec_start < e2.header.nsec_start)
        return -1;
    if (e1.header.nsec_start > e2.header.nsec_start)
        return 1;
    return 0;
}


// Initialize the "joiner" state machine
static int sstate_init(struct state *st) {
    st->is_logging = 0;
    st->st = ST_SCANNING;
    st->last_run_offset = 0;
    st->join_buffer_capacity = 0;
    st->buffer_offset = -1;
    st->search_limit = 0;
    return 0;
}

static int sstate_state(struct state *st) {
    return st->st;
}

static int sstate_run(struct state *st) {
    return st_funcs[st->st](st);
}

static int sstate_set(struct state *st, enum prog_state new_state) {
    st->st = new_state;
    return 0;
}



// Dummy state that should never be reached
static int st_uninitialized(struct state *st) {
    printf("state error: should not be in this state\n");
    return -1;
}

// Searching for either a NAND block or a sync point
static int st_scanning(struct state *st) {
    int ret;
    union evt evt;

    hdr_count = 0;
    lseek(st->fd, 0, SEEK_SET);
    do {
        int s = lseek(st->fd, 0, SEEK_CUR);
        if (s == -1) {
            perror("Couldn't seek");
            exit(1);
        }
        hdrs[hdr_count++] = s;
    } while ((ret = event_get_next(st, &evt)) == 0);
    hdr_count--;
    printf("Working on %d events, last ret was %d...\n", hdr_count, ret);

    sstate_set(st, ST_GROUPING);
    return 0;
}

static int st_grouping(struct state *st) {
    printf("Sorting...\n");
    qsort(hdrs, hdr_count, sizeof(*hdrs), compare_event_addrs);
    sstate_set(st, ST_DONE);
    return 0;
}


/* We're all done sorting.  Write out the logfile.
 * Format:
 *   Magic number 0x43 0x9f 0x22 0x53
 *   Number of elements
 *   Array of absolute offsets from the start of the file
 *   Magic number 0xa4 0xc3 0x2d 0xe5
 *   Array of events
 */
static int st_done(struct state *st) {
    int jump_offset;
    uint32_t word;
    uint32_t offset;

    printf("Writing out...\n");
    lseek(st->out_fd, 0, SEEK_SET);
    offset = 0;

    // Write out magic
    write(st->out_fd, EVENT_HDR_1, sizeof(EVENT_HDR_1));
    offset += sizeof(EVENT_HDR_1);

    // Write out how many header items there are
    word = htonl(hdr_count);
    write(st->out_fd, &word, sizeof(word));
    offset += sizeof(word);

    // Advance the offset past the jump table
    offset += hdr_count*sizeof(offset);

    // Read in the jump table entries
    lseek(st->fd, 0, SEEK_SET);
    for (jump_offset=0; jump_offset<hdr_count; jump_offset++) {
        union evt evt;
        uint32_t offset_swab = htonl(offset);
        write(st->out_fd, &offset_swab, sizeof(offset_swab));

        lseek(st->fd, hdrs[jump_offset], SEEK_SET);
        memset(&evt, 0, sizeof(evt));
        event_get_next(st, &evt);
        if (evt.header.size > 32768)
            exit(1);
        offset += evt.header.size;
    }

    write(st->out_fd, EVENT_HDR_2, sizeof(EVENT_HDR_2));
    offset += sizeof(EVENT_HDR_2);

    // Now copy over the exact events
    lseek(st->fd, 0, SEEK_SET);
    for (jump_offset=0; jump_offset<hdr_count; jump_offset++) {
        union evt evt;
        lseek(st->fd, hdrs[jump_offset], SEEK_SET);
        event_get_next(st, &evt);
        event_write(st, &evt);
    }

    printf("Done.\n");
    exit(0);
    return 0;
}



int main(int argc, char **argv) {
    struct state state;
    int ret;

    g_st = &state;
    memset(&state, 0, sizeof(state));

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [in_filename] [out_filename]\n", argv[0]);
        return 1;
    }

    ret = open_files(&state, argv[1], argv[2]);
    if (ret)
        return ret;

    sstate_init(&state);
    while (!ret)
        ret = sstate_run(&state);
    printf("State machine finished with result: %d\n", ret);

    return 0;
}

