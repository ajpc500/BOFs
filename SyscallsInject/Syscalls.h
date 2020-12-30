#pragma once

#include <windows.h>


WINBASEAPI int WINAPI KERNEL32$lstrcmp (LPCSTR lpString1, LPCSTR lpString2);
WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsA (LPCSTR, LPSTR, DWORD);

WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict _Dst,const void * __restrict _Src,size_t _MaxCount);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileMappingA (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT WINBASEAPI PVOID WINAPI KERNEL32$MapViewOfFile (HANDLE, DWORD, DWORD, DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$UnmapViewOfFile (LPCVOID);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle (HANDLE);

#define NTDLL_PATH "%SystemRoot%\\system32\\NTDLL.dll"

typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
	HANDLE             ProcessHandle,
	PVOID             *BaseAddress,
	ULONG_PTR          ZeroBits,
	PSIZE_T            RegionSize,
	ULONG              AllocationType,
	ULONG              Protect);

typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
	HANDLE             ProcessHandle,
	PVOID             *BaseAddress,
	IN OUT PSIZE_T     RegionSize,
	ULONG              FreeType);

typedef NTSTATUS (NTAPI *NtOpenProcess_t)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId);
  
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
	HANDLE             hProcess,
	PVOID              lpBaseAddress,
	PVOID              lpBuffer,
	SIZE_T             NumberOfBytesToRead,
	PSIZE_T            NumberOfBytesRead);
  
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t) (
  PHANDLE            ThreadHandle, 
  ACCESS_MASK        DesiredAccess, 
  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
  HANDLE             ProcessHandle,
  PVOID              StartRoutine,
  PVOID              Argument OPTIONAL,
  ULONG              CreateFlags,
  ULONG_PTR          ZeroBits, 
  SIZE_T             StackSize OPTIONAL,
  SIZE_T             MaximumStackSize OPTIONAL, 
  PVOID              AttributeList OPTIONAL);
    
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(
  HANDLE             ObjectHandle,
  BOOLEAN            Alertable,
  PLARGE_INTEGER     TimeOut OPTIONAL); 
  
typedef NTSTATUS (NTAPI *NtClose_t)(
  HANDLE             ObjectHandle);
  
typedef struct _syscall_t {
    NtOpenProcess_t           NtOpenProcess;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
    NtWriteVirtualMemory_t    NtWriteVirtualMemory;
    NtCreateThreadEx_t        NtCreateThreadEx;
    NtWaitForSingleObject_t   NtWaitForSingleObject;
    NtFreeVirtualMemory_t     NtFreeVirtualMemory;
    NtClose_t                 NtClose;
} syscall_t;




#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }


ULONG64 rva2ofs(PIMAGE_NT_HEADERS nt, DWORD rva) {
    PIMAGE_SECTION_HEADER sh;
    int                   i;
    
    if(rva == 0) return -1;
    
    sh = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
           nt->FileHeader.SizeOfOptionalHeader);
    
    for(i = nt->FileHeader.NumberOfSections - 1; i >= 0; i--) {
      if(sh[i].VirtualAddress <= rva &&
        rva <= (DWORD)sh[i].VirtualAddress + sh[i].SizeOfRawData)
      {
        return sh[i].PointerToRawData + rva - sh[i].VirtualAddress;
      }
    }
    return -1;
}

LPVOID GetProcAddress2(LPBYTE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    PIMAGE_SECTION_HEADER   sh;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD                   rva, ofs, cnt, nos;
    PCHAR                   str;
    PDWORD                  adr, sym;
    PWORD                   ord;
    
    if(hModule == NULL || lpProcName == NULL) return NULL;
    
    dos = (PIMAGE_DOS_HEADER)hModule;
    nt  = (PIMAGE_NT_HEADERS)(hModule + dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    
    // no exports? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(rva == 0) return NULL;
    
    ofs = rva2ofs(nt, rva);
    if(ofs == -1) return NULL;
    
    // no exported symbols? exit
    exp = (PIMAGE_EXPORT_DIRECTORY)(ofs + hModule);
    cnt = exp->NumberOfNames;
    if(cnt == 0) return NULL;
    
    // read the array containing address of api names
    ofs = rva2ofs(nt, exp->AddressOfNames);        
    if(ofs == -1) return NULL;
    sym = (PDWORD)(ofs + hModule);

    // read the array containing address of api
    ofs = rva2ofs(nt, exp->AddressOfFunctions);        
    if(ofs == -1) return NULL;
    adr = (PDWORD)(ofs + hModule);
    
    // read the array containing list of ordinals
    ofs = rva2ofs(nt, exp->AddressOfNameOrdinals);
    if(ofs == -1) return NULL;
    ord = (PWORD)(ofs + hModule);
    
    // scan symbol array for api string
    do {
      str = (PCHAR)(rva2ofs(nt, sym[cnt - 1]) + hModule);
      // found it?
      if(KERNEL32$lstrcmp(str, lpProcName) == 0) {
        // return the address
        return (LPVOID)(rva2ofs(nt, adr[ord[cnt - 1]]) + hModule);
      }
    } while (--cnt);
    return NULL;
}

LPVOID GetSyscallStub(LPCSTR lpSyscallName) {
    HANDLE                        file = NULL, map = NULL;
    LPBYTE                        mem = NULL;
    LPVOID                        cs = NULL;
    PIMAGE_DOS_HEADER             dos;
    PIMAGE_NT_HEADERS             nt;
    PIMAGE_DATA_DIRECTORY         dir;
    PIMAGE_RUNTIME_FUNCTION_ENTRY rf;
    ULONG64                       ofs, start=0, end=0, addr;
    SIZE_T                        len;
    DWORD                         i, rva;
    CHAR                          path[MAX_PATH];
    
    KERNEL32$ExpandEnvironmentStringsA(NTDLL_PATH, path, MAX_PATH);
    
    // open file
    file = KERNEL32$CreateFileA((LPCWSTR)path, 
      GENERIC_READ, FILE_SHARE_READ, NULL, 
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(file == INVALID_HANDLE_VALUE) { goto cleanup; }
    
    // create mapping
    map = KERNEL32$CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if(map == NULL) { goto cleanup; }
    
    // create view
    mem = (LPBYTE)KERNEL32$MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if(mem == NULL) { goto cleanup; }
    
    // try resolve address of system call
    addr = (ULONG64)GetProcAddress2(mem, lpSyscallName);
    if(addr == 0) { goto cleanup; }
    
    dos = (PIMAGE_DOS_HEADER)mem;
    nt  = (PIMAGE_NT_HEADERS)((PBYTE)mem + dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    
    // no exception directory? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    if(rva == 0) { goto cleanup; }
    
    ofs = rva2ofs(nt, rva);
    if(ofs == -1) { goto cleanup; }
    
    rf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(ofs + mem);

    // for each runtime function (there might be a better way??)
    for(i=0; rf[i].BeginAddress != 0; i++) {
      // is it our system call?
      start = rva2ofs(nt, rf[i].BeginAddress) + (ULONG64)mem;
      if(start == addr) {
        // save the end and calculate length
        end = rva2ofs(nt, rf[i].EndAddress) + (ULONG64)mem;
        len = (SIZE_T) (end - start);

        // allocate RWX memory
        cs = KERNEL32$VirtualAlloc(NULL, len, 
          MEM_COMMIT | MEM_RESERVE,
          PAGE_EXECUTE_READWRITE);
          
        if(cs != NULL) {
          // copy system call code stub to memory
          MSVCRT$memcpy(cs, (const void*)start, len);
        }
        break;
      }
    }
    
cleanup:
    if(mem != NULL) KERNEL32$UnmapViewOfFile(mem);
    if(map != NULL) KERNEL32$CloseHandle(map);
    if(file != NULL) KERNEL32$CloseHandle(file);
    
    // return pointer to code stub or NULL
    return cs;
}