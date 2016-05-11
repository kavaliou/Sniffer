#include "packetbase.h"

PacketBase::PacketBase(const u_char* data)
{
    (void)data;
    protocol = "OTHER";
    source = "";
    destination = "";
    type = 0;
}

QString PacketBase::ParseHeader(const u_char *data){
    (void)data;
    return NULL;
}
