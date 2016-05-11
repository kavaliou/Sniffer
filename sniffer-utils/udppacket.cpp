#include "udppacket.h"

UDPPacket::UDPPacket(const u_char *data, const pcap_pkthdr *header, int offset) : PacketBase(data)
{
    protocol ="UDP";

    struct sockaddr_in src, dest;
    struct iphdr *iph = (struct iphdr *)(data + offset);

    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = iph->saddr;
    source = strdup(inet_ntoa(src.sin_addr));

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    destination = strdup(inet_ntoa(dest.sin_addr));

    type = 3;
    this->offset = offset;
    parsedData = this->ParseHeader(data, header->len);
}

QString UDPPacket::ParseHeader(const u_char *data, int size) {
    QString resultString;
    resultString = QString::fromUtf8("******UDP Packet********\n");
    return resultString;
}
