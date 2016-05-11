#include "tcppacket.h"

#include <QDebug>

TCPPacket::TCPPacket(const u_char *data, int offset) : PacketBase(data)
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
    parsedData = this->ParseHeader(data);
}

QString TCPPacket::ParseHeader(const u_char *data) {
    struct tcphdr *tcph=(struct tcphdr*)(data + offset);

    QString resultString;
    resultString = QString::fromUtf8("*****TCP Packet***********\n");

    char num_buffer [100];
    sprintf(num_buffer, "   |-Source Port      : %u\n", ntohs(tcph->source));
    resultString += QString::fromUtf8(num_buffer);
    sprintf(num_buffer, "   |-Destination Port : %u\n", ntohs(tcph->dest));
    resultString += QString::fromUtf8(num_buffer);
//    fprintf(logfile , );
//    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
//    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
//    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
//    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
//    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
//    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
//    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
//    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
//    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
//    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
//    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
//    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
//    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
//    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
//    fprintf(logfile , "\n");
//    fprintf(logfile , "                        DATA Dump                         ");
//    fprintf(logfile , "\n");
    return resultString;

}
