#ifndef SNIFFER_H
#define SNIFFER_H

#include<pcap.h>
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

#include "protocol_codes.h"
#include "tcppacket.h"
#include "udppacket.h"
#include "arppacket.h"

#include <QThread>
#include <QList>

class Sniffer : public QThread
{
    Q_OBJECT

public:
    Sniffer(QThread *parent = 0);
    ~Sniffer();
public slots:

private slots:
    void savePacket(PacketBase *packet);

signals:
    void PacketRecieved(PacketBase *packet);

private:
    QList<PacketBase> *packetList;

    void processPacket(u_char *args, const pcap_pkthdr *header, const u_char *buffer);

protected:
    void run();
};



#endif // SNIFFER_H
