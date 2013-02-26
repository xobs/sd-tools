#include <stdio.h>
#include <stdint.h>
#include "state.h"

enum control_pins {
    NAND_ALE = 2,
    NAND_CLE = 1,
    NAND_WE = 4,
    NAND_RE = 8,
    NAND_CS = 16,
    NAND_RB = 32,
};

static uint8_t order[] = {
	4,	// Known
	5,	// Known
	6,	// Known
	7,	// Known

	3,	// Known
	2,	// Known
	1,	// Known
	0,	// Known
};

uint8_t nand_unscramble_byte(uint8_t byte) {
	return (
		  ( (!!(byte&(1<<order[0]))) << 0)
		| ( (!!(byte&(1<<order[1]))) << 1)
		| ( (!!(byte&(1<<order[2]))) << 2)
		| ( (!!(byte&(1<<order[3]))) << 3)
		| ( (!!(byte&(1<<order[4]))) << 4)
		| ( (!!(byte&(1<<order[5]))) << 5)
		| ( (!!(byte&(1<<order[6]))) << 6)
		| ( (!!(byte&(1<<order[7]))) << 7)
	);
}

int nand_print(struct state *st, uint8_t data, uint8_t ctrl) {
    printf("NAND %02x %c %c %c %c %c %c\n",
            data,
            ctrl&NAND_ALE?'A':' ',
            ctrl&NAND_CLE?'C':' ',
            ctrl&NAND_WE?'W':' ',
            ctrl&NAND_RE?'R':' ',
            ctrl&NAND_CS?'S':' ',
            ctrl&NAND_RB?'B':' ');
    return 0;
}

uint8_t nand_ale(uint8_t ctrl) {
    return ctrl&NAND_ALE;
}

uint8_t nand_cle(uint8_t ctrl) {
    return ctrl&NAND_CLE;
}

uint8_t nand_we(uint8_t ctrl) {
    return ctrl&NAND_WE;
}

uint8_t nand_re(uint8_t ctrl) {
    return ctrl&NAND_RE;
}

uint8_t nand_cs(uint8_t ctrl) {
    return ctrl&NAND_CS;
}

uint8_t nand_rb(uint8_t ctrl) {
    return ctrl&NAND_RB;
}
