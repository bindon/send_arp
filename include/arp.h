#ifndef _ARP_H
#define _ARP_H
#include <main.h>
#include <util.h>
#define IN
#define OUT

int receiveArpPacket(IN pcap_t *handle, IN uint8_t *senderIpAddress, OUT arpStructure *receivedArpPacket);
int getSenderMacAddress(IN pcap_t *handle, IN char *interfaceName, IN char *senderIpAddress, OUT uint8_t *senderMacAddress);
int spoofMacAddress(IN pcap_t *handle, IN char *interfaceName, IN char *senderIpAddress, IN char *targetIpAddress, IN uint8_t *senderMacAddress);
#endif
