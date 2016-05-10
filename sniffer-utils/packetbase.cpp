#include "packetbase.h"

PacketBase::PacketBase(const u_char* data)
{
    (void)data;
    protocol = "OTHER";
    source = "";
    destination = "";
    this->data = data;
    type = 0;
}
