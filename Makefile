CC=g++
CFLAG=-lpcap

all : send_arp

send_arp:
	@$(CC) -o send_arp main.cpp $(CFLAG)

clean:
	@rm -f send_arp
	@rm -f *.o

