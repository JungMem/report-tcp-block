all: tcp-block

main.o: ess_func.h main.c

send.o: checksum.h ess_libnet.h send.h send.c

tcp-block: main.o send.o
	gcc -o tcp-block send.o main.o -lpcap

clean:
	rm -f tcp-block *.o
