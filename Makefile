CC=gcc
CFLAGS=-pedantic -Wall -O2 
programs=afserver afclient
security=server.rsa client.rsa cacert.pem

all: compi $(programs) ok1 secure

afserver: afserver.c network.o file.o stats.o buflist.o
	$(CC) $(CFLAGS) -lssl -lz afserver.c network.o file.o stats.o buflist.o -o afserver

afclient: afclient.c network.o stats.o buflist.o
	$(CC) $(CFLAGS) -rdynamic -lssl -lz -ldl afclient.c network.o stats.o buflist.o -o afclient

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $*.c

exmodule: exmodule.c
	$(CC) -fPIC $(CFLAGS) -c $@.c
	$(CC) $(CFLAGS) -shared -o $@ $@.o

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
	rm -rf a.out *~ *.o $(programs) $(security) exmodule
