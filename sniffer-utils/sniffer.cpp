#include "sniffer.h"

#include <QThread>
#include <QDebug>


Sniffer::Sniffer(QThread *parent) :
    QThread(parent)
{
    packetList = new QList<PacketBase>();
    connect(this, SIGNAL(PacketProcessed(PacketBase*)), this, SLOT(savePacket(PacketBase*)));
    filterType = 0;
}

Sniffer::~Sniffer()
{
    delete packetList;
    this->terminate();
    this->wait();
}

void Sniffer::GetPackets(int type)
{
    filterType = type;
    QList<PacketBase> *temp = new QList<PacketBase>();
    QList<PacketBase>::iterator i;
    switch(type){
    case 0:
        emit PacketPushed(packetList);
        break;
    case 1:
        for (i = packetList->begin(); i != packetList->end(); ++i){
            if (i->getTypeID() == 2 || i->getTypeID() == 3)
                temp->append(*i);
        }
        emit PacketPushed(temp);
        break;
    case 2:
        for (i = packetList->begin(); i != packetList->end(); ++i){
            if (i->getTypeID() == 4)
                temp->append(*i);
        }
        emit PacketPushed(temp);
        break;
    }
}

void Sniffer::savePacket(PacketBase *packet)
{
    packet->id = packetList->count() + 1;
    packetList->append(*packet);
    switch(filterType){
    case 0:
        emit PacketRecieved(packet);
        break;
    case 1:
        if (packet->getTypeID() == 2 || packet->getTypeID() == 3)
            emit PacketRecieved(packet);
        break;
    case 2:
        if (packet->getTypeID() == 4)
            emit PacketRecieved(packet);
        break;
    }
}

PacketBase *processPPPoE(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer + 22);
    switch (iph->protocol) {
    case 6: {
        TCPPacket* packet = new TCPPacket(buffer, 22);
        return packet;
    }
    case 17: {
        UDPPacket* packet = new UDPPacket(buffer, 22);
        return packet;
    }
    default: {
        PacketBase* packet = new PacketBase(buffer);
        return packet;
    }
    }
}

PacketBase *processIP(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer + 14);
    PacketBase* packet;
    switch (iph->protocol) {
    case 6: {
        packet = new TCPPacket(buffer, 14);
        return packet;
    }
    case 17: {
        packet = new UDPPacket(buffer, 14);
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
        emit PacketProcessed(processPPPoE(buffer));
        break;
    case IP_PROTOCOL_CODE:
        emit PacketProcessed(processIP(buffer));
        break;
    case ARP_PROTOCOL_CODE:
        emit PacketProcessed(new ARPPacket(buffer));
        break;
    default:
        break;
    }
}

QString Sniffer::GetPacketParsedData(int id)
{
    QList<PacketBase>::iterator i;
    for (i = packetList->begin(); i != packetList->end(); ++i){
        if ((*i).id == id){
            return (*i).parsedData;
        }
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
