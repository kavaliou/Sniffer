#ifndef ARPPACKET_H
#define ARPPACKET_H

#include "packetbase.h"

class ARPPacket : public PacketBase
{
public:
    ARPPacket(const u_char *data);
};

#endif // ARPPACKET_H
