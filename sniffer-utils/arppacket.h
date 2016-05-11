#ifndef ARPPACKET_H
#define ARPPACKET_H

#include "packetbase.h"

class ARPPacket : public PacketBase
{
public:
    ARPPacket(const u_char *data, const pcap_pkthdr *header);
    QString ParseHeader(const u_char *data, int size);
};

#endif // ARPPACKET_H
