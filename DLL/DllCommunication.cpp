#include "stdafx.h"
#include "DllCommunication.h"
#include "OspeDll.h"
#include "FilterManager.h"
#include <sstream>
#include "Utils.h"
#include "HookedFunctions.h"


//#define DBG_BLOCKPKT // blocked packets debug
//#define DBG_SENDPACKETDATA // packet data debug

char readData[IPC_BLOCK_SIZE];



// Add to info the socket information (ip, port) and also the type of function and size of the packet
bool SetInfo(SOCKET socket, Functions functionId, int length, PacketInfo* info)
{
	//char ipstr[INET6_ADDRSTRLEN];
	BYTE ipver = IPV4;

	struct sockaddr_storage addrLocal;
	struct sockaddr_storage addrRemote;
	socklen_t addr_len = sizeof(struct sockaddr_storage);

	if (getsockname(socket, (struct sockaddr*)&addrLocal, &addr_len) == SOCKET_ERROR)
		Utils::errorLog(Utils::strm(2, "getsockname: ", Utils::IntToString(WSAGetLastError())));

	if (getpeername(socket, (struct sockaddr*)&addrRemote, &addr_len) == SOCKET_ERROR)
		return false;
		//Utils::errorLog(Utils::strm(2, "getpeername: ", Utils::IntToString(WSAGetLastError())));

	// deal with both IPv4 and IPv6:
	if (addrLocal.ss_family == AF_INET)
	{
		info->localIp = htonl(((struct sockaddr_in *)&addrLocal)->sin_addr.s_addr);
		info->localPort = htons(((struct sockaddr_in *)&addrLocal)->sin_port);

		info->remoteIp = htonl(((struct sockaddr_in *)&addrRemote)->sin_addr.s_addr);
		info->remotePort = htons(((struct sockaddr_in *)&addrRemote)->sin_port);

	}
	else
	{ //Not Implemented yet
		
		// AF_INET6
		
		Utils::errorLog("CRASH ALERT: IPv6 SOCKET NOT IMPLEMENTED");
		//struct sockaddr_in6 *sock_addr = (struct sockaddr_in6 *)&addrFrom;
		//info->portFrom = ntohs(sock_addr->sin6_port);
		//inet_ntop(AF_INET6, &sock_addr->sin6_addr, ipstr, sizeof ipstr);
		ipver = IPV6;
	}

	// Send the protocol version through "functionId"

	info->functionId = (Functions)(functionId | ipver);
	info->socketId = socket;
	info->size = length;

	return true;
}

// This method writes the packet to the memory mapped file then returns
void ProcessPacket(Functions functionId, char*& buffer, int& length, SOCKET socket, bool& blocked)
{
	
	char* name = (char*)malloc(IPC_MAX_NAME);
	sprintf(name, "%s%u", "OSPEPACKETBUFF", GetCurrentProcessId());
	static osIPC::Client client(name);


	if (!client.IsOk())
	{
#ifdef DBG_SENDPACKETDATA 
		Utils::errorLog("Fail to open MMF!!", 1);
#endif
		return;
	}

	

	// Set needed packet info (ip, port, Function, Size)
	PacketInfo info;
	if (socket != NULL)
	{
		if ((int)length == 0) // ignore empty packets
			return;

		if (SetInfo(socket, functionId, (int)length, &info) != true)
			return;		
	}
	else 
	{
		info.functionId = functionId;
		info.localIp = 0;
		info.localPort = 0;
		info.remoteIp = 0;
		info.remotePort = 0;
		info.size = length;
		info.socketId = 0;
	}

	// Set data


#ifdef DBG_SENDPACKETDATA
	std::stringstream sinfo;
	sinfo << "GOT Info - FunctionID=" << info.functionId << " LocalIp=" << info.localIp << " LocalPort=" << info.localPort << " RemoteIp="
		<< info.remoteIp << " RemotePort=" << info.remotePort << " Size=" << info.size;
	Utils::errorLog((char*)sinfo.str().c_str(), 2);
#endif


		

	char* pBuff = (char *) malloc(sizeof(info) + sizeof(buffer) + length + 1);
	memcpy(pBuff, &info, sizeof(info));
	memcpy(pBuff + sizeof(info), buffer, length);

	

	bool breakpoint = false;
	if (isFiltering)
		// Only filter if it wasn't blocked, makes no sense filter a blocked packet
		if (!CheckPacketBlock(pBuff + sizeof(info), info.size, (FilterCaptureFuncs)info.functionId))
			// If filter is a Breakpoint filter then stop filtering
			if (!CheckPacketBreak(pBuff + sizeof(info), info.size, (FilterCaptureFuncs)info.functionId)) {
				if (DoFilteringForPacket(pBuff + sizeof(info), info.size, (FilterCaptureFuncs)info.functionId))
					// Copy new filtered data
					memcpy((void*)buffer, pBuff + sizeof(info), length);
			}
			else 
				breakpoint = true;							
		else
			blocked = true;
	
	

	client.write(pBuff, sizeof(info) + length); // Send the packet to ospe

	if (breakpoint)
	{
		hMainThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
		SuspendThread(hMainThread); // Suspend thread until we receive new data from ospe
		UINT16 newLength = 0; 
		newLength = ((UINT8)readData[2] << 8) | ((UINT8)readData[1]); // Set the length for the new packet
		length = newLength;
		buffer = (char *)malloc(length);
		memcpy((void*)buffer, &readData[3], length); // read new data
	}	
	
	free(pBuff);

	
}

void ProcessPacket(Functions functionId, char*& buffer, int& length) 
{
	bool blocked = false;
	ProcessPacket(functionId, buffer, length, NULL, blocked);
}

void InjectPacket() 
{
	SOCKET s = ((static_cast<size_t>((UINT8)readData[2]) << 8) | static_cast<size_t>((UINT8)readData[1]));
	int len = ((static_cast<size_t>((UINT8)readData[4]) << 8) | static_cast<size_t>((UINT8)readData[3]));
	const char * buf = &readData[5];
	int flags = MSG_DONTROUTE;
	send(s, buf, len, flags);
}


// Command reader thread worker
DWORD WINAPI Command_Reader(LPVOID context)
{
    // Continuously read data
    for (;;)
    {
        server.read(readData, IPC_BLOCK_SIZE, INFINITE);
		ServerCodes sc = (ServerCodes)readData[0];
		switch (sc)
		{
			case SCODE_INJECTPACKET:
				InjectPacket();
				break;
			case SCODE_SETPACKET:
				ResumeThread(hMainThread);
				break;
			case SCODE_STARTFILTERING:
				{		
					CovertBytesToFilterList(readData);
					isFiltering = true;
				}
				break;
			case SCODE_STOPFILTERING:
				isFiltering = false;
				break;
			case SCODE_STARTCAPTURE:
				isCapturing = true;
				break;
			case SCODE_STOPCAPTURE:
				isCapturing = false;
				break;
			case SCODE_LOADDLLEX:
				LoadDllEx(&readData[1]);
				break;
			case SCODE_UNLOADDLLEX:
				UnLoadDllEx();
				break;
			default:
				Utils::errorLog("UNKNOWN SERVER CODE!");
		}

    }

    // Success
    return 0;
};

