# Beacon Object Files

1. ETW Patching
2. API Function Utility
3. Syscalls Shellcode Injection

## ETW Patching BOF

Simple Beacon object file to patch (and revert) the EtwEventWrite function in ntdll.dll to degrade ETW based logging.

All credit goes to @xpn: https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/.


## API Function Utility BOF

Beacon object file to:
- Read bytes of loaded module API function
- Read relevant on-disk DLL and compare functions to identify differencies (e.g. EPP/EDR hooking)
- Patch functions with the on-disk copy (i.e. API unhooking)

Credit goes to @spottheplanet for the Dll parsing technique: https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time


## Syscalls Shellcode Injection BOF (64-bit only)

Beacon object file to:
- Fetch Syscall Stubs from on-disk ntdll.dll (All credit to @odzhan - https://github.com/odzhan/injection/blob/master/syscalls/inject_dll.c)
- Inject shellcode (either custom or beacon) into remote process using NtOpenProcess -> NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtCreateThreadEx.

Credit also to @tomcarver16 for their DLL inject BOF and aggressor script (https://github.com/tomcarver16/BOF-DLL-Inject)
