#ifndef TCPPACKET_H
#define TCPPACKET_H

#include "packetbase.h"

class TCPPacket : public PacketBase
{
public:
    TCPPacket(const u_char *data);
};

#endif // TCPPACKET_H
