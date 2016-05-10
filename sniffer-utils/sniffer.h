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

#include <QThread>


class Sniffer : public QThread
{
    Q_OBJECT

public:
    Sniffer(QThread *parent = 0);

public slots:

signals:
    void PacketRecieved(const char *protocol);

private:

protected:
    void processPacket(u_char *args, const pcap_pkthdr *header, const u_char *buffer);
    void run();
};



#endif // SNIFFER_H
