CC=gcc
CFLAGS=-pedantic -Wall -O2 
programs=afserver afclient
security=server.rsa client.rsa cacert.pem

all: compi $(programs) ok1 secure

afserver: afserver.c network.o file.o stats.o
	$(CC) $(CFLAGS) -lssl -lz afserver.c network.o file.o stats.o -o afserver

afclient: afclient.c network.o stats.o
	$(CC) $(CFLAGS) -lssl -lz afclient.c network.o stats.o -o afclient

network.o: network.c network.h
	$(CC) $(CFLAGS) -c network.c

file.o: file.c file.h
	$(CC) $(CFLAGS) -c file.c

stats.o: stats.c stats.h
	$(CC) $(CFLAGS) -c stats.c

secure: crea $(security) ok2

server.rsa: 
	@openssl genrsa -rand Makefile -out server.rsa 2048
	
client.rsa: 
	@openssl genrsa -rand server.rsa -out client.rsa 2048
	
cacert.pem:
	@echo -e "\n Generating certificate...\n"
	@echo -e "pl\nWar-Maz\nOlsztyn\nSHEG\nUtils productions\njeremian\njeremian@poczta.fm" | openssl req -new -x509 -key server.rsa -out cacert.pem -days 1095 > /dev/null 2>&1

compi:
	@echo -e "\nCompiling program...\n"

crea:
	@echo -e "\nCreating necessary files...\n"

ok1:
	@echo "  OK!"

ok2:
	@echo "  OK!"

.PHONY: clean

clean:
	rm -rf a.out *~ *.o $(programs) $(security)
