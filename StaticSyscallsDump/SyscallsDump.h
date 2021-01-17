#pragma once

#include <windows.h>

#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define OBJ_CASE_INSENSITIVE 0x00000040L

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);

DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
WINBASEAPI char WINAPI MSVCRT$strcat(char *destination, const char *source);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strtok(char * __restrict__ _Str,const char * __restrict__ _Delim);

WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict _Dst,const void * __restrict _Src,size_t _MaxCount);
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

//ADVAPI32
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);

//DBG
WINBASEAPI BOOL __cdecl DBGHELP$MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
