all:
	$(CC) joiner.c packet.c nand.c -o joiner -Wall -g
	$(CC) grouper.c packet.c nand.c groups.c -o grouper -Wall -g
