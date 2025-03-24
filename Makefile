CFLAGS:=-Wall -Wextra -Werror -pedantic -std=c23 -g -pthread
CC:=clang

all: server client

server:
	$(CC) $(CFLAGS) -o server server.c

client:
	$(CC) $(CFLAGS) -o client client.c

clean:
	rm server client
