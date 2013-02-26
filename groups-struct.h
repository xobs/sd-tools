#ifndef __GROUPS_H__
#define __GROUPS_H__

#define GROUP_MAGIC_1 0x61728394
#define GROUP_MAGIC_2 0x74931723

#include <stdint.h>
struct state;
struct pkt;

enum grp_type {
    GRP_HELLO,
    GRP_SD_CMD,
    GRP_BUFFER_DRAIN,
    GRP_NET_CMD,
    GRP_RESET,
    GRP_NAND_ID,
    GRP_NAND_STATUS,
    GRP_NAND_PARAMETER_READ,
    GRP_NAND_READ,
    GRP_NAND_CHANGE_READ_COLUMN,
    GRP_NAND_UNKNOWN,
    GRP_NAND_RESET,
    GRP_NAND_CACHE1 = 0x30,
    GRP_NAND_CACHE2 = 0x31,
    GRP_NAND_CACHE3 = 0x32,
    GRP_NAND_CACHE4 = 0x33,
    GRP_NAND_SANDISK_VENDOR_START   = 0x60,
    GRP_NAND_SANDISK_VENDOR_PARAM   = 0x61,
    GRP_NAND_SANDISK_CHARGE1        = 0x62,
    GRP_NAND_SANDISK_CHARGE2        = 0x63,
};

struct grp_header {
    uint8_t type;
    uint32_t sec_start, nsec_start;
    uint32_t sec_end, nsec_end;
    uint32_t size;
} __attribute__((__packed__));



// A full SD command (including response)
struct grp_sd_cmd {
    struct grp_header hdr;
    uint8_t  cmd;    // High bit set if it's ACMD
    uint32_t num_args;
    uint8_t  args[1024];
    uint32_t num_results;
    uint8_t  result[1024]; // If it's CMD17, contains a sector
    uint8_t  reserved;
} __attribute__((__packed__));


// When the FPGA buffer is drained
struct grp_buffer_drain {
    struct grp_header hdr;
} __attribute__((__packed__));


// When the FPGA is reset.
struct grp_reset {
    struct grp_header hdr;
    uint8_t version;
} __attribute__((__packed__));


// A network command
struct grp_net_cmd {
    struct grp_header hdr;
    uint8_t  cmd[2];
    uint32_t arg;
} __attribute__((__packed__));


// Encapsulates the HELLO packet
struct grp_hello {
    struct grp_header hdr;
    uint32_t magic1;
    uint8_t version;
    uint32_t magic2;
} __attribute__((__packed__));


// When the NAND starts up, it gives an ID packet (0x90 aa ss ss ss ss ss ss ss ss)
struct grp_nand_id {
    struct grp_header hdr;
    uint8_t addr;
    uint8_t id[8];
} __attribute__((__packed__));


// The challenge (and response) of a NAND "status" query (0x70 ss)
struct grp_nand_status {
    struct grp_header hdr;
    uint8_t status;
} __attribute__((__packed__));


// Read a page of NAND (0x05 aa bb cc dd 0xe0 ...)
struct grp_nand_change_read_column {
    struct grp_header hdr;
    uint8_t addr[5];
    uint32_t count;
    uint8_t data[16384];
    uint8_t unknown[2];
} __attribute__((__packed__));

struct grp_nand_read {
    struct grp_header hdr;
    uint8_t addr[5];
    uint32_t count;
    uint8_t data[16384];
    uint8_t unknown[2];
} __attribute__((__packed__));

    


// Parameter page read (0xec aa ...)
struct grp_nand_parameter_read {
    struct grp_header hdr;
    uint8_t addr;
    uint16_t count;
    uint8_t data[256];
} __attribute__((__packed__));

// Unknown address set (charge, maybe?) (0x65 aa bb cc)
struct grp_nand_sandisk_charge1 {
    struct grp_header hdr;
    uint8_t addr[3];
} __attribute__((__packed__));

// Unknown address set (charge, maybe?) (0x60 aa bb cc 0x30)
struct grp_nand_sandisk_charge2 {
    struct grp_header hdr;
    uint8_t addr[3];
} __attribute__((__packed__));

// Unknown set vendor code (0x5c 0xc5)
struct grp_nand_unk_sandisk_code {
    struct grp_header hdr;
} __attribute__((__packed__));

// Set vendor parameter (when in vendor-code mode above) (0x55 aa dd)
struct grp_nand_unk_sandisk_param {
    struct grp_header hdr;
    uint8_t addr;
    uint8_t data;
} __attribute__((__packed__));

// We have no idea
struct grp_nand_unk_command {
    struct grp_header hdr;
    uint8_t command;
    uint8_t num_addrs;
    uint8_t addrs[256];
    uint8_t num_data;
    uint8_t data[4096];
    uint8_t unknown[2]; // Average of the "unknown" pins
} __attribute__((__packed__));

// We have no idea and we're lost
struct grp_nand_unk {
    struct grp_header hdr;
    uint8_t data;
    uint8_t ctrl;
    uint16_t unknown;
} __attribute__((__packed__));

struct grp_nand_reset {
    struct grp_header hdr;
} __attribute__((__packed__));

struct grp_nand_cache1 {
    struct grp_header hdr;
} __attribute__((__packed__));

struct grp_nand_cache2 {
    struct grp_header hdr;
} __attribute__((__packed__));

struct grp_nand_cache3 {
    struct grp_header hdr;
} __attribute__((__packed__));

struct grp_nand_cache4 {
    struct grp_header hdr;
} __attribute__((__packed__));


int grp_fill_header(void *arg, uint32_t sec_start, uint32_t nsec_start,
                    uint32_t size, uint8_t type);
int grp_fill_end(void *arg,
                 uint32_t sec_end, uint32_t nsec_end);
int grp_write_hello(struct state *st, struct pkt *pkt);
int grp_write_reset(struct state *st, struct pkt *pkt);
int grp_write_nand_unk(struct state *st, struct pkt *pkt);

#endif //__GROUPS_H__
