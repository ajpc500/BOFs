#pragma once
#include "Syscalls.h"

#define ZwClose NtClose
__asm__("NtClose: \n\
	mov rax, gs:[0x60]              \n\
NtClose_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 5 \n\
	je  NtClose_SystemCall_5_X_XXXX \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtClose_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtClose_Check_10_0_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 0 \n\
	je  NtClose_Check_6_0_XXXX \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtClose_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtClose_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtClose_SystemCall_6_3_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_0_XXXX:                \n\
	cmp word ptr [rax+0x120], 6000 \n\
	je  NtClose_SystemCall_6_0_6000 \n\
	cmp word ptr [rax+0x120], 6001 \n\
	je  NtClose_SystemCall_6_0_6001 \n\
	cmp word ptr [rax+0x120], 6002 \n\
	je  NtClose_SystemCall_6_0_6002 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtClose_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtClose_SystemCall_6_1_7601 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtClose_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtClose_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtClose_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtClose_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtClose_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtClose_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtClose_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtClose_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtClose_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtClose_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtClose_SystemCall_10_0_19042 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_SystemCall_5_X_XXXX:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_0_6000:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_0_6001:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_0_6002:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_1_7600:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_1_7601:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x000d \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x000e \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10240:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10586:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_14393:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_15063:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_16299:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17134:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17763:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18362:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18363:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19041:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19042:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_Unknown:            \n\
	ret \n\
NtClose_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwQueueApcThread NtQueueApcThread
__asm__("NtQueueApcThread: \n\
	mov rax, gs:[0x60]                           \n\
NtQueueApcThread_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtQueueApcThread_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtQueueApcThread_Check_10_0_XXXX \n\
	jmp NtQueueApcThread_SystemCall_Unknown \n\
NtQueueApcThread_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtQueueApcThread_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtQueueApcThread_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtQueueApcThread_SystemCall_6_3_XXXX \n\
	jmp NtQueueApcThread_SystemCall_Unknown \n\
NtQueueApcThread_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtQueueApcThread_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtQueueApcThread_SystemCall_6_1_7601 \n\
	jmp NtQueueApcThread_SystemCall_Unknown \n\
NtQueueApcThread_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtQueueApcThread_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtQueueApcThread_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtQueueApcThread_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtQueueApcThread_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtQueueApcThread_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtQueueApcThread_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtQueueApcThread_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtQueueApcThread_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtQueueApcThread_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtQueueApcThread_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtQueueApcThread_SystemCall_10_0_19042 \n\
	jmp NtQueueApcThread_SystemCall_Unknown \n\
NtQueueApcThread_SystemCall_6_1_7600:           \n\
	mov eax, 0x0042 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_6_1_7601:           \n\
	mov eax, 0x0042 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0043 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0044 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_10240:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_10586:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_14393:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_15063:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_16299:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_17134:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_17763:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_18362:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_18363:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_19041:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_10_0_19042:         \n\
	mov eax, 0x0045 \n\
	jmp NtQueueApcThread_Epilogue \n\
NtQueueApcThread_SystemCall_Unknown:            \n\
	ret \n\
NtQueueApcThread_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwResumeThread NtResumeThread
__asm__("NtResumeThread: \n\
	mov rax, gs:[0x60]                         \n\
NtResumeThread_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtResumeThread_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtResumeThread_Check_10_0_XXXX \n\
	jmp NtResumeThread_SystemCall_Unknown \n\
NtResumeThread_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtResumeThread_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtResumeThread_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtResumeThread_SystemCall_6_3_XXXX \n\
	jmp NtResumeThread_SystemCall_Unknown \n\
NtResumeThread_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtResumeThread_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtResumeThread_SystemCall_6_1_7601 \n\
	jmp NtResumeThread_SystemCall_Unknown \n\
NtResumeThread_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtResumeThread_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtResumeThread_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtResumeThread_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtResumeThread_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtResumeThread_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtResumeThread_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtResumeThread_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtResumeThread_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtResumeThread_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtResumeThread_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtResumeThread_SystemCall_10_0_19042 \n\
	jmp NtResumeThread_SystemCall_Unknown \n\
NtResumeThread_SystemCall_6_1_7600:           \n\
	mov eax, 0x004f \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_6_1_7601:           \n\
	mov eax, 0x004f \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0050 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0051 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_10240:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_10586:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_14393:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_15063:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_16299:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_17134:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_17763:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_18362:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_18363:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_19041:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_10_0_19042:         \n\
	mov eax, 0x0052 \n\
	jmp NtResumeThread_Epilogue \n\
NtResumeThread_SystemCall_Unknown:            \n\
	ret \n\
NtResumeThread_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwCreateSection NtCreateSection
__asm__("NtCreateSection: \n\
	mov rax, gs:[0x60]                          \n\
NtCreateSection_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtCreateSection_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtCreateSection_Check_10_0_XXXX \n\
	jmp NtCreateSection_SystemCall_Unknown \n\
NtCreateSection_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtCreateSection_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtCreateSection_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtCreateSection_SystemCall_6_3_XXXX \n\
	jmp NtCreateSection_SystemCall_Unknown \n\
NtCreateSection_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtCreateSection_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtCreateSection_SystemCall_6_1_7601 \n\
	jmp NtCreateSection_SystemCall_Unknown \n\
NtCreateSection_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtCreateSection_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtCreateSection_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtCreateSection_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtCreateSection_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtCreateSection_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtCreateSection_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtCreateSection_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtCreateSection_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtCreateSection_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtCreateSection_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtCreateSection_SystemCall_10_0_19042 \n\
	jmp NtCreateSection_SystemCall_Unknown \n\
NtCreateSection_SystemCall_6_1_7600:           \n\
	mov eax, 0x0047 \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_6_1_7601:           \n\
	mov eax, 0x0047 \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0048 \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0049 \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_10240:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_10586:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_14393:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_15063:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_16299:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_17134:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_17763:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_18362:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_18363:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_19041:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_10_0_19042:         \n\
	mov eax, 0x004a \n\
	jmp NtCreateSection_Epilogue \n\
NtCreateSection_SystemCall_Unknown:            \n\
	ret \n\
NtCreateSection_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwMapViewOfSection NtMapViewOfSection
__asm__("NtMapViewOfSection: \n\
	mov rax, gs:[0x60]                             \n\
NtMapViewOfSection_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtMapViewOfSection_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtMapViewOfSection_Check_10_0_XXXX \n\
	jmp NtMapViewOfSection_SystemCall_Unknown \n\
NtMapViewOfSection_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtMapViewOfSection_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtMapViewOfSection_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtMapViewOfSection_SystemCall_6_3_XXXX \n\
	jmp NtMapViewOfSection_SystemCall_Unknown \n\
NtMapViewOfSection_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtMapViewOfSection_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtMapViewOfSection_SystemCall_6_1_7601 \n\
	jmp NtMapViewOfSection_SystemCall_Unknown \n\
NtMapViewOfSection_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtMapViewOfSection_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtMapViewOfSection_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtMapViewOfSection_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtMapViewOfSection_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtMapViewOfSection_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtMapViewOfSection_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtMapViewOfSection_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtMapViewOfSection_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtMapViewOfSection_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtMapViewOfSection_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtMapViewOfSection_SystemCall_10_0_19042 \n\
	jmp NtMapViewOfSection_SystemCall_Unknown \n\
NtMapViewOfSection_SystemCall_6_1_7600:           \n\
	mov eax, 0x0025 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_6_1_7601:           \n\
	mov eax, 0x0025 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0026 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0027 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_10240:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_10586:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_14393:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_15063:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_16299:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_17134:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_17763:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_18362:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_18363:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_19041:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_10_0_19042:         \n\
	mov eax, 0x0028 \n\
	jmp NtMapViewOfSection_Epilogue \n\
NtMapViewOfSection_SystemCall_Unknown:            \n\
	ret \n\
NtMapViewOfSection_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwUnmapViewOfSection NtUnmapViewOfSection
__asm__("NtUnmapViewOfSection: \n\
	mov rax, gs:[0x60]                               \n\
NtUnmapViewOfSection_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtUnmapViewOfSection_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtUnmapViewOfSection_Check_10_0_XXXX \n\
	jmp NtUnmapViewOfSection_SystemCall_Unknown \n\
NtUnmapViewOfSection_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtUnmapViewOfSection_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtUnmapViewOfSection_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtUnmapViewOfSection_SystemCall_6_3_XXXX \n\
	jmp NtUnmapViewOfSection_SystemCall_Unknown \n\
NtUnmapViewOfSection_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtUnmapViewOfSection_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtUnmapViewOfSection_SystemCall_6_1_7601 \n\
	jmp NtUnmapViewOfSection_SystemCall_Unknown \n\
NtUnmapViewOfSection_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtUnmapViewOfSection_SystemCall_10_0_19042 \n\
	jmp NtUnmapViewOfSection_SystemCall_Unknown \n\
NtUnmapViewOfSection_SystemCall_6_1_7600:           \n\
	mov eax, 0x0027 \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_6_1_7601:           \n\
	mov eax, 0x0027 \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0028 \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0029 \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_10240:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_10586:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_14393:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_15063:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_16299:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_17134:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_17763:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_18362:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_18363:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_19041:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_10_0_19042:         \n\
	mov eax, 0x002a \n\
	jmp NtUnmapViewOfSection_Epilogue \n\
NtUnmapViewOfSection_SystemCall_Unknown:            \n\
	ret \n\
NtUnmapViewOfSection_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

