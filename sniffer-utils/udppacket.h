#ifndef UDPPACKET_H
#define UDPPACKET_H

#include "packetbase.h"

class UDPPacket : public PacketBase
{
public:
    UDPPacket(const u_char *data, int offset);
    QString ParseHeader(const u_char *data);
};

#endif // UDPPACKET_H
