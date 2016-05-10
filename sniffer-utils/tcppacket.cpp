#include "tcppacket.h"

TCPPacket::TCPPacket(const u_char *data) : PacketBase(data)
{
    protocol = "TCP";

    struct sockaddr_in src, dest;
    struct iphdr *iph = (struct iphdr *)(data + 22);

    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = iph->saddr;
    source = strdup(inet_ntoa(src.sin_addr));

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    destination = strdup(inet_ntoa(dest.sin_addr));

    type = 2;
}
