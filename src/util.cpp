#include <util.h>

// Print MAC Address in Ethernet Packet
void printMacAddress(IN const char *prefix, IN uint8_t *macAddress) {
    printf("%s[%02x:%02x:%02x:%02x:%02x:%02x]\n", prefix,
        macAddress[0], macAddress[1], macAddress[2],
        macAddress[3], macAddress[4], macAddress[5]);
}

// Print IP Address
void printIpAddress(IN const char *prefix, IN uint8_t *ipAddress) {
    printf("%s[%d.%d.%d.%d]\n", prefix,
        ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
}

// Get MAC Address using Interface Name
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

// Get IP Address using Interface Name
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

// Print ARP Packet Information
void printArpPacketInfo(IN arpStructure arpPacket) {
    printMacAddress("  - Sender MAC Address : ", (uint8_t *)arpPacket.senderHardwareAddress);
    printMacAddress("  - Target MAC Address : ", (uint8_t *)arpPacket.targetHardwareAddress);
    printIpAddress( "  - Sender IP  Address : ", (uint8_t *)arpPacket.senderProtocolAddress);
    printIpAddress( "  - Target IP  Address : ", (uint8_t *)arpPacket.targetProtocolAddress);
}

