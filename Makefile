all:
	$(CC) joiner.c packet.c nand.c -o joiner -Wall -g
	$(CC) grouper.c packet.c nand.c events.c -o grouper -Wall -g
	$(CC) sorter.c packet.c nand.c events.c -o sorter -Wall -g
