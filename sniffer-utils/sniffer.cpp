#include "sniffer.h"

#include <QThread>
#include <QDebug>


Sniffer::Sniffer(QThread *parent) :
    QThread(parent)
{
    packetList = new QList<PacketBase>();
    connect(this, SIGNAL(PacketRecieved(PacketBase*)), this, SLOT(savePacket(PacketBase*)));
}

Sniffer::~Sniffer()
{
    delete packetList;
    this->terminate();
    this->wait();
}

void Sniffer::savePacket(PacketBase *packet)
{
    packetList->append(*packet);
}

PacketBase *processPPPoE(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer + 22);
    PacketBase* packet;
    switch (iph->protocol) {
    case 6: {
        packet = new TCPPacket(buffer);
        return packet;
    }
    case 17: {
        packet = new UDPPacket(buffer);
        return packet;
    }
    default: {
        packet = new PacketBase(buffer);
        return packet;
    }
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
        emit PacketRecieved(new ARPPacket(buffer));
        break;
    default:
//        qDebug() << ethh->h_proto;
        break;
    }
}

void Sniffer::run()
{
    char errbuf[2000];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr hdr;

    handle = pcap_open_live("eth0", 65536 , 1 , 0 , errbuf);
    if (handle == NULL)
    {
        qDebug() << "Couldn't open device";
        return;
    }

    while (1) {
        packet = pcap_next(handle, &hdr);
        if(packet == NULL){
        } else {
            processPacket(NULL, &hdr, packet);
        }
    }
}
