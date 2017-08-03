default: all

all: server client

server: server.c
	gcc -g -o server server.c -lssl -lcrypto -lpthread

clean:
	-rm -f server
	-rm -f client

client: client.c
	gcc -g -o client client.c -lssl -lcrypto
