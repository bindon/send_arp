#ifndef _MAIN_H
#define _MAIN_H
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

// Parameter Flag
#define IN
#define OUT

// Ethernet Constants
#define ETHERNET_TYPE_ARP 0x0806

// ARP Constants
#define ARP_HARDWARE_TYPE_ETHERNET   0x01
#define ARP_PROTOCOL_TYPE_IP         0x0800
#define ARP_HARDWARE_LENGTH_ETHERNET 0x06
#define ARP_PROTOCOL_LENGTH_IP       0x04
#define ARP_OPERATION_REQUEST        0x01
#define ARP_OPERATION_REPLY          0x02
#define RARP_OPERATION_REQUEST       0x03
#define RARP_OPERATION_REPLY         0x04

#pragma pack(push, 1)
// Ethernet Header Structure
typedef struct _ethernetHeader {
    uint8_t  destinationMac[6];
    uint8_t  sourceMac[6];
    uint16_t type;
} ethernetHeader;

// ARP Packet Structure
typedef struct _arpStructure {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t  hardwareLength;
    uint8_t  protocolLength;
    uint16_t operationCode;
    uint8_t  senderHardwareAddress[ARP_HARDWARE_LENGTH_ETHERNET];
    uint8_t  senderProtocolAddress[ARP_PROTOCOL_LENGTH_IP];
    uint8_t  targetHardwareAddress[ARP_HARDWARE_LENGTH_ETHERNET];
    uint8_t  targetProtocolAddress[ARP_PROTOCOL_LENGTH_IP];
} arpStructure;

// Ethernet + ARP Packet Structure
typedef struct _mergedStructure {
    ethernetHeader ethernetPacket;
    arpStructure   arpPacket;
} mergedStructure;
#pragma pack(pop)
#endif
