# Makefile
LDLIBS += -lpcap

all: pcap-test

# pcap-test: pcap-test.c

pcap-test: net_headers.o main.o
	gcc -o pcap-test net_headers.o main.o -lpcap

main.o: net_headers.h main.c

net_headers.o: net_headers.h net_headers.c

clean:
	rm -f pcap-test *.o

