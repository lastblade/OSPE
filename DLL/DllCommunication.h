#ifndef DLLCOMMUNICATION_H
#define DLLCOMMUNICATION_H

#include <ws2tcpip.h>
#include "Defines.h"


#define SOCKET_ERROR            (-1)
#define IPV4 0
#define IPV6 128


bool SetInfo(SOCKET socket, Functions functionId, int length, PacketInfo* info);
void ProcessPacket(Functions functionId, char*& buffer, int& length, SOCKET socket, bool& blocked);
void ProcessPacket(Functions functionId, char*& buffer, int& length);


DWORD WINAPI Command_Reader(LPVOID context);


#endif // DLLCOMMUNICATION_H