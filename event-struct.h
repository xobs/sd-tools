#ifndef __EVENT_STRUCT_H_
#define __EVENT_STRUCT_H_

#define EVENT_MAGIC_1 0x61728394
#define EVENT_MAGIC_2 0x74931723

#include <stdint.h>
struct state;
struct pkt;

enum evt_type {
    EVT_HELLO,
    EVT_SD_CMD,
    EVT_BUFFER_DRAIN,
    EVT_NET_CMD,
    EVT_RESET,
    EVT_NAND_ID,
    EVT_NAND_STATUS,
    EVT_NAND_PARAMETER_READ,
    EVT_NAND_READ,
    EVT_NAND_CHANGE_READ_COLUMN,
    EVT_NAND_UNKNOWN,
    EVT_NAND_RESET,
    EVT_UNKNOWN,
    EVT_NAND_CACHE1 = 0x30,
    EVT_NAND_CACHE2 = 0x31,
    EVT_NAND_CACHE3 = 0x32,
    EVT_NAND_CACHE4 = 0x33,
    EVT_NAND_SANDISK_VENDOR_START   = 0x60,
    EVT_NAND_SANDISK_VENDOR_PARAM   = 0x61,
    EVT_NAND_SANDISK_CHARGE1        = 0x62,
    EVT_NAND_SANDISK_CHARGE2        = 0x63,
};

struct evt_header {
    uint8_t type;
    uint32_t sec_start, nsec_start;
    uint32_t sec_end, nsec_end;
    uint32_t size;
} __attribute__((__packed__));



// A full SD command (including response)
struct evt_sd_cmd {
    struct evt_header hdr;
    uint8_t  cmd;    // High bit set if it's ACMD
    uint32_t num_args;
    uint8_t  args[1024];
    uint32_t num_results;
    uint8_t  result[1024]; // If it's CMD17, contains a sector
    uint8_t  reserved;
} __attribute__((__packed__));


// When the FPGA buffer is drained
struct evt_buffer_drain {
    struct evt_header hdr;
} __attribute__((__packed__));


// When the FPGA is reset.
struct evt_reset {
    struct evt_header hdr;
    uint8_t version;
} __attribute__((__packed__));


// A network command
struct evt_net_cmd {
    struct evt_header hdr;
    uint8_t  cmd[2];
    uint32_t arg;
} __attribute__((__packed__));


// Encapsulates the HELLO packet
struct evt_hello {
    struct evt_header hdr;
    uint32_t magic1;
    uint8_t version;
    uint32_t magic2;
} __attribute__((__packed__));


// When the NAND starts up, it gives an ID packet (0x90 aa ss ss ss ss ss ss ss ss)
struct evt_nand_id {
    struct evt_header hdr;
    uint8_t addr;
    uint8_t size;
    uint8_t id[8];
} __attribute__((__packed__));


// The challenge (and response) of a NAND "status" query (0x70 ss)
struct evt_nand_status {
    struct evt_header hdr;
    uint8_t status;
} __attribute__((__packed__));


// Read a page of NAND (0x05 aa bb cc dd 0xe0 ...)
struct evt_nand_change_read_column {
    struct evt_header hdr;
    uint8_t addr[5];
    uint32_t count;
    uint8_t data[16384];
    uint8_t unknown[2];
} __attribute__((__packed__));

struct evt_nand_read {
    struct evt_header hdr;
    uint8_t addr[5];
    uint32_t count;
    uint8_t data[16384];
    uint8_t unknown[2];
} __attribute__((__packed__));

    


// Parameter page read (0xec aa ...)
struct evt_nand_parameter_read {
    struct evt_header hdr;
    uint8_t addr;
    uint16_t count;
    uint8_t data[256];
} __attribute__((__packed__));

// Unknown address set (charge, maybe?) (0x65 aa bb cc)
struct evt_nand_sandisk_charge1 {
    struct evt_header hdr;
    uint8_t addr[3];
} __attribute__((__packed__));

// Unknown address set (charge, maybe?) (0x60 aa bb cc 0x30)
struct evt_nand_sandisk_charge2 {
    struct evt_header hdr;
    uint8_t addr[3];
} __attribute__((__packed__));

// Unknown set vendor code (0x5c 0xc5)
struct evt_nand_unk_sandisk_code {
    struct evt_header hdr;
} __attribute__((__packed__));

// Set vendor parameter (when in vendor-code mode above) (0x55 aa dd)
struct evt_nand_unk_sandisk_param {
    struct evt_header hdr;
    uint8_t addr;
    uint8_t data;
} __attribute__((__packed__));

// We have no idea
struct evt_nand_unk_command {
    struct evt_header hdr;
    uint8_t command;
    uint8_t num_addrs;
    uint8_t addrs[256];
    uint8_t num_data;
    uint8_t data[4096];
    uint8_t unknown[2]; // Average of the "unknown" pins
} __attribute__((__packed__));

// We have no idea and we're lost
struct evt_nand_unk {
    struct evt_header hdr;
    uint8_t data;
    uint8_t ctrl;
    uint16_t unknown;
} __attribute__((__packed__));

struct evt_nand_reset {
    struct evt_header hdr;
} __attribute__((__packed__));

struct evt_nand_cache1 {
    struct evt_header hdr;
} __attribute__((__packed__));

struct evt_nand_cache2 {
    struct evt_header hdr;
} __attribute__((__packed__));

struct evt_nand_cache3 {
    struct evt_header hdr;
} __attribute__((__packed__));

struct evt_nand_cache4 {
    struct evt_header hdr;
} __attribute__((__packed__));



union evt {
    struct evt_header header;
    struct evt_sd_cmd sd_cmd;
    struct evt_buffer_drain buffer_drain;
    struct evt_reset reset;
    struct evt_net_cmd net_cmd;
    struct evt_hello hello;
    struct evt_nand_id nand_id;
    struct evt_nand_status nand_status;
    struct evt_nand_change_read_column nand_change_read_coumn;
    struct evt_nand_read nand_read;
    struct evt_nand_parameter_read nand_parameter_read;
    struct evt_nand_sandisk_charge1 nand_sandisk_charge1;
    struct evt_nand_sandisk_charge2 nand_sandisk_charge2;
    struct evt_nand_unk_sandisk_code nand_unk_sandisk_code;
    struct evt_nand_unk_sandisk_param nand_unk_sandisk_param;
    struct evt_nand_unk_command nand_unk_command;
    struct evt_nand_unk nand_unk;
    struct evt_nand_reset nand_reset;
    struct evt_nand_cache1 nand_cache1;
    struct evt_nand_cache2 nand_cache2;
    struct evt_nand_cache3 nand_cache3;
    struct evt_nand_cache4 nand_cache4;
} __attribute__((__packed__));

int evt_fill_header(void *arg, uint32_t sec_start, uint32_t nsec_start,
                    uint32_t size, uint8_t type);
int evt_fill_end(void *arg,
                 uint32_t sec_end, uint32_t nsec_end);
int evt_write_hello(struct state *st, struct pkt *pkt);
int evt_write_reset(struct state *st, struct pkt *pkt);
int evt_write_nand_unk(struct state *st, struct pkt *pkt);

#endif //__EVENT_STRUCT_H_
