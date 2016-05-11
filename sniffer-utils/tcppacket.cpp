#include "tcppacket.h"

#include <QDebug>

TCPPacket::TCPPacket(const u_char *data, const pcap_pkthdr *header, int offset) : PacketBase(data)
{
    protocol = "TCP";

    struct sockaddr_in src, dest;
    struct iphdr *iph = (struct iphdr *)(data + offset);

    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = iph->saddr;
    source = strdup(inet_ntoa(src.sin_addr));

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    destination = strdup(inet_ntoa(dest.sin_addr));

    type = 2;
    this->offset = offset;
    parsedData = this->ParseHeader(data, header->len);
}

QString Data(const u_char* data, int size){
    QString resultString, dString = QString::fromUtf8("");
    char num_buffer [100];
    resultString = QString::fromUtf8("       DATA Dump       \n");

    int i , j;
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            sprintf(num_buffer, "         ");
            resultString += QString::fromUtf8(num_buffer);
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    sprintf(num_buffer, "%c", (unsigned char)data[j]);
                else sprintf(num_buffer, ".");
                dString += QString::fromUtf8(num_buffer);
            }
            sprintf(num_buffer, "\n");
            dString += QString::fromUtf8(num_buffer);
            resultString += QString::fromUtf8(num_buffer);
        }
        sprintf(num_buffer, "%02X ",(unsigned int)data[i]);
        resultString += QString::fromUtf8(num_buffer);
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              sprintf(num_buffer, "   "); //extra spaces
              resultString += QString::fromUtf8(num_buffer);
            }
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  sprintf(num_buffer, "%c",(unsigned char)data[j]);
                  dString += QString::fromUtf8(num_buffer);
                }
                else
                {
                  sprintf(num_buffer, ".");
                  dString += QString::fromUtf8(num_buffer);
                }
            }
            sprintf(num_buffer, "\n" );
            dString += QString::fromUtf8(num_buffer);
            resultString += QString::fromUtf8(num_buffer);
        }
    }
    sprintf(num_buffer, "\n");
    resultString += QString::fromUtf8(num_buffer);
    return resultString + dString;
}

QString TCPPacket::ParseHeader(const u_char *data, int size) {
    struct tcphdr *tcph=(struct tcphdr*)(data + offset);
    int header_size = offset + sizeof(struct tcphdr);
    QString resultString;
    char num_buffer [100];
    resultString = QString::fromUtf8("*****TCP Packet***********\n");
    sprintf(num_buffer, "   |-Source Port      : %u\n", ntohs(tcph->source));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Destination Port : %u\n", ntohs(tcph->dest));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Window         : %d\n",ntohs(tcph->window));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Checksum       : %d\n",ntohs(tcph->check));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    resultString += QString::fromUtf8(num_buffer);
    resultString += Data(data + header_size, header_size);
    return resultString;

}
