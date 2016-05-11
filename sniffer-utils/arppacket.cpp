#include "arppacket.h"

ARPPacket::ARPPacket(const u_char *data) : PacketBase(data)
{
    protocol = "ARP";
    source = "IntelCor__33:90:23";
    destination = "Broadcast";
    type = 4;
    offset = 0;
}

QString ARPPacket::ParseHeader(const u_char *data) {
    QString resultString;
    resultString = QString::fromUtf8("******ARP Packet********\n");
    return resultString;
}
