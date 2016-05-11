#ifndef PACKETBASE_H
#define PACKETBASE_H

#include <QString>

#include <string.h> //for memset
#include <cstring>

#include <pcap.h>
#include <sys/types.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header


class PacketBase
{
public:
    PacketBase(const u_char *data);
    char* source;
    char* destination;
    const char* protocol;
    int offset;
    int id;
    QString parsedData;

    QString ParseHeader(const u_char *data, int size);

    int getTypeID(){
        return type;
    }


protected:
    int type;
};

#endif // PACKETBASE_H
