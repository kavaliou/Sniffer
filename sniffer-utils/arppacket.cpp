#include "arppacket.h"

ARPPacket::ARPPacket(const u_char *data) : PacketBase(data)
{
    protocol = "ARP";
    source = "IntelCor__33:90:23";
    destination = "Broadcast";
    type = 4;
}
