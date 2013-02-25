#ifndef __PACKET_H__
#define __PACKET_H__
#include <stdint.h>

enum subsystem_ids {
	SUBSYS_NONE = 0,
	SUBSYS_SD = 1,
	SUBSYS_NET = 2,
	SUBSYS_FPGA = 3,
	SUBSYS_PARSE = 4,
	SUBSYS_PKT = 5,
};

enum fpga_errs {
	FPGA_ERR_UNKNOWN_PKT,
	FPGA_ERR_OVERFLOW,
};

enum buffer_drain_start_stop {
	PKT_BUFFER_DRAIN_START = 1,
	PKT_BUFFER_DRAIN_STOP = 2,
};

enum pkt_cmd_start_stop {
	CMD_START = 1,
	CMD_STOP = 2,
};

enum buffer_number {
	BUFFER_WRITE = 1,
	BUFFER_READ = 2,
	SECTOR_OFFSET = 3,
};

enum pkt_type {
	PACKET_UNKNOWN = 0,
	PACKET_ERROR = 1,
	PACKET_NAND_CYCLE = 2,
	PACKET_SD_DATA = 3,
	PACKET_SD_CMD_ARG = 4,
	PACKET_SD_RESPONSE = 5,
	PACKET_SD_CID = 6,
	PACKET_SD_CSD = 7,
	PACKET_BUFFER_OFFSET = 8,
	PACKET_BUFFER_CONTENTS = 9,
	PACKET_COMMAND = 10,
	PACKET_RESET = 11,
	PACKET_BUFFER_DRAIN = 12,
	PACKET_HELLO = 13,
};


struct pkt_header {
	uint8_t type;
	uint32_t sec;
	uint32_t nsec;
	uint16_t size;
} __attribute__((__packed__));



struct pkt_error {
	uint8_t subsystem;
	uint8_t code;
	uint16_t arg;
	uint8_t message[512];
} __attribute__((__packed__));

struct pkt_nand_cycle {
	uint8_t data;
	uint8_t control;
	uint16_t unknown;
} __attribute__((__packed__));

struct pkt_sd_data {
	uint8_t data[512];
} __attribute__((__packed__));

struct pkt_sd_cmd_arg {
	uint8_t reg;
	uint8_t val;
} __attribute__((__packed__));

struct pkt_sd_response {
	uint8_t byte;
} __attribute__((__packed__));

struct pkt_sd_cid {
	uint8_t cid[16];
} __attribute__((__packed__));

struct pkt_sd_csd {
	uint8_t csd[16];
} __attribute__((__packed__));

struct pkt_buffer_offset {
	uint8_t number;
	uint32_t offset;
} __attribute__((__packed__));

struct pkt_buffer_contents {
	uint8_t number;
	uint8_t contents[512];
} __attribute__((__packed__));

struct pkt_command {
	uint8_t cmd[2];
	uint32_t arg;
	uint8_t start_stop;
} __attribute__((__packed__));

struct pkt_reset {
	uint8_t version;
} __attribute__((__packed__));

struct pkt_buffer_drain {
	uint8_t start_stop;
} __attribute__((__packed__));

struct pkt_hello {
	uint8_t version;
} __attribute__((__packed__));


union pkt_data {
    struct pkt_error error;
    struct pkt_nand_cycle nand_cycle;
    struct pkt_sd_data sd_data;
    struct pkt_sd_cmd_arg sd_cmd_arg;
    struct pkt_sd_response response;
    struct pkt_sd_cid cid;
    struct pkt_sd_csd csd;
    struct pkt_buffer_offset buffer_offset;
    struct pkt_buffer_contents buffer_contents;
    struct pkt_command command;
    struct pkt_reset reset;
	struct pkt_buffer_drain buffer_drain;
	struct pkt_hello hello;
} __attribute__((__packed__));

struct pkt {
	struct pkt_header header;
	union pkt_data data;
} __attribute__((__packed__));



#endif // __PACKET_H__
