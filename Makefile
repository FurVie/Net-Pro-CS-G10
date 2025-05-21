CC = gcc
CFLAGS = -Wall -Wextra -g $(shell pkg-config --cflags gtk+-3.0)
LDFLAGS = -lssl -lcrypto $(shell pkg-config --libs gtk+-3.0) -lpthread

all: server client

server: server.c
	$(CC) $(CFLAGS) -o server.exe server.c $(LDFLAGS)

client: client.c
	$(CC) $(CFLAGS) -o client.exe client.c $(LDFLAGS)

clean:
	del /F /Q server.exe client.exe 