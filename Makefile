all:
	$(CC) joiner.c packet.c nand.c -o joiner -Wall -g
	$(CC) parser.c packet.c nand.c -o parser -Wall -g
