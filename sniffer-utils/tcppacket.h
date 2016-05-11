#ifndef TCPPACKET_H
#define TCPPACKET_H

#include "packetbase.h"

class TCPPacket : public PacketBase
{
public:
    TCPPacket(const u_char *data, const pcap_pkthdr *header, int offset);
    QString ParseHeader(const u_char *data, int size);
};

#endif // TCPPACKET_H
