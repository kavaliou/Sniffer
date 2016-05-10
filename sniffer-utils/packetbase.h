#ifndef PACKETBASE_H
#define PACKETBASE_H

#include <string.h> //for memset
#include <cstring>

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
    const u_char* data;

    int getTypeID(){
        return type;
    }

protected:
    int type;
};

#endif // PACKETBASE_H
