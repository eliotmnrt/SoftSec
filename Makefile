CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -L. -lclient -lserver -lssl -lcrypto

all: client server

client: sectrans_client.c
	$(CC) $(CFLAGS) -o client sectrans_client.c $(LDFLAGS)

server: sectrans_server.c
	$(CC) $(CFLAGS) -o server sectrans_server.c $(LDFLAGS)

clean:
	rm -f client server