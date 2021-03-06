#ifndef _UTIL_H
#define _UTIL_H
#include <main.h>
#define IN
#define OUT
void printMacAddress(IN const char *prefix, IN uint8_t *macAddress);
void printIpAddress(IN const char *prefix, IN uint8_t *ipAddress);
int getMacAddress(IN char *interfaceName, OUT uint8_t *macAddress);
int getIpAddress(IN char *interfaceName, OUT uint8_t *ipAddress);
void printArpPacketInfo(IN arpStructure arpPacket);
#endif
