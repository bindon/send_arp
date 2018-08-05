#ifndef _ARP_H
#define _ARP_H
#include <main.h>
#include <util.h>
#define IN
#define OUT

void receiveArpPacket(IN pcap_t *handle, IN uint8_t *macAddress, OUT arpStructure *receivedArpPacket);
int getVictimMacAddress(IN pcap_t *handle, IN char *interfaceName, IN char *victimIpAddress, OUT uint8_t *victimMacAddress);
int spoofMacAddress(IN pcap_t *handle, IN char *interfaceName, IN char *victimIpAddress, IN char *gatewayIpAddress, IN uint8_t *victimMacAddress);
#endif
