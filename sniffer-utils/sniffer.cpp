#include "sniffer.h"

#include <QThread>
#include <QDebug>


Sniffer::Sniffer(QThread *parent) :
    QThread(parent)
{
}

int packetCount = 0, matter = 0;

char* processPPPoE(const u_char *buffer){
    buffer += 22;
    struct iphdr *iph = (struct iphdr*)(buffer);
    switch (iph->protocol) {
    case 6:
        return "TCP";
        break;
    case 17:
        return "UDP";
        break;
    default:
        return "OTHER";
        break;
    }
}


void Sniffer::processPacket(u_char *args, const pcap_pkthdr *header, const u_char *buffer)
{
    (void)args;
    (void)header;

    struct ethhdr *ethh = (struct ethhdr*)(buffer);

    switch (ethh->h_proto) {
    case PPPOE_SESSION_PROTOCOL_CODE:
        emit PacketRecieved(processPPPoE(buffer));
        break;
    case ARP_PROTOCOL_CODE:
        emit PacketRecieved("ARP");
        break;
    default:
        break;
    }
}

void Sniffer::run()
{
    char errbuf[2000];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr hdr;

    qDebug() << "Opening device for sniffing ... ";

    handle = pcap_open_live("eth0", 65536 , 1 , 0 , errbuf);

    if (handle == NULL)
    {
        qDebug() << "Couldn't open device";
        return;
    }
    qDebug() << "Done";

    while (1) {
        packet = pcap_next(handle, &hdr);
        if(packet == NULL){
        } else {
            processPacket(NULL, &hdr, packet);
        }
    }
}





