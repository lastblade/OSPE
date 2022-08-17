#ifndef WEPEDLL_H
#define WEPEDLL_H

#include <string>
#include <vector>
#include <winsock2.h>
#include <Windows.h>
#include <tlhelp32.h> 
#include "ipc.h"

extern bool isCapturing;
extern bool isFiltering;

extern HMODULE hDllEx;
extern HANDLE hMainThread;

void LoadDllEx(LPCSTR lpFileName);
void UnLoadDllEx();

// Create the IPC client
static osIPC::Server server;


#endif // WEPEDLL_H
