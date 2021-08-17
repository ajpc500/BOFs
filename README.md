# Beacon Object Files

| Name                                         | Syntax                 | 
| -------------------------------------------- | ---------------------- | 
| ETW Patching                                 | `etw stop` / `etw start`   | 
| API Function Utility                         | `read_function` / `check_function` / `patch_function <dll_path> <function_name>` | 
| Syscalls Shellcode Injection                 | `syscalls_inject <PID> <listener_name>` / `syscalls_shinject <PID> <path_to_bin>` | 
| Spawn and Syscalls Shellcode Injection       | `syscalls_spawn <listener>` / `syscalls_shspawn <path_to_bin>` | 
| Spawn and Static Syscalls Shellcode Injection (NtQueueApcThread)           | `static_syscalls_apc_spawn <listener>` / `static_syscalls_apc_spawn <path_to_bin>` | 
| Static Syscalls Shellcode Injection (NtCreateThreadEx)         | `static_syscalls_inject <PID> <listener_name>` / `static_syscalls_shinject <PID> <path_to_bin>` | 
| Static Syscalls Process Dump                 | `static_syscalls_dump <PID> [path_to_output]` | 
| Curl | `curl host [port] [method] [--show] [useragent] [headers] [body]` |



## ETW Patching BOF

Simple Beacon object file to patch (and revert) the EtwEventWrite function in ntdll.dll to degrade ETW based logging.

All credit goes to @xpn: https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/.


## API Function Utility BOF

Beacon object file to:
- Read bytes of loaded module API function
- Read relevant on-disk DLL and compare functions to identify differencies (e.g. EPP/EDR hooking)
- Patch functions with the on-disk copy (i.e. API unhooking)

Credit goes to @spotheplanet for the Dll parsing technique: https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time


## Syscalls Shellcode Injection BOF (64-bit only)

Beacon object file to:
- Fetch Syscall Stubs from on-disk ntdll.dll (All credit to @odzhan - https://github.com/odzhan/injection/blob/master/syscalls/inject_dll.c)
- Inject shellcode (either custom or beacon) into remote process using NtOpenProcess -> NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtCreateThreadEx.

Credit also to @tomcarver16 for their DLL inject BOF and aggressor script (https://github.com/tomcarver16/BOF-DLL-Inject)


## Spawn with Syscalls Shellcode Injection BOF (64-bit only)

Same syscalls injection process as SyscallsInject (above) but uses `BeaconSpawnTemporaryProcess` to create the target process.

## Spawn with Syscalls Shellcode Injection (NtMapViewOfSection -> NtQueueApcThread) BOF (64-bit only)

NtCreateSection -> NtMapViewOfSection -> NtQueueApcThread -> NtResumeThead.
Uses `BeaconSpawnTemporaryProcess` to create the target process.

Syscalls generated using @jthuraisamy's [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), @FalconForce's [SysWhispers2BOF](https://github.com/FalconForceTeam/SysWhispers2BOF) and @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

Code adapted from @peperunas's [injectopi](https://github.com/peperunas/injectopi/blob/master/CreateSectionAPC/CreateSectionAPC.cpp)

## Static Syscalls Shellcode Injection BOF (64-bit only)

Beacon object file to:
- Inject shellcode (either custom or beacon) into remote process using NtOpenProcess -> NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtCreateThreadEx.

Same injection process as above, but using static Syscalls, rather than stubs fetched from Ntdll.

Syscalls generated using @jthuraisamy's [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), @FalconForce's [SysWhispers2BOF](https://github.com/FalconForceTeam/SysWhispers2BOF) and @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

## Static Syscalls Process Dump BOF (64-bit only)

Beacon object file to:
- Unhook NtReadVirtualMemory function.
- Create process memory dump using MiniDumpWriteDump function to specified (or default) location

Syscalls generated using @jthuraisamy's [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), @FalconForce's [SysWhispers2BOF](https://github.com/FalconForceTeam/SysWhispers2BOF) and @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

This is effectively a rough port of @Outflank's [Dumpert](https://github.com/outflanknl/Dumpert) tool. All credit to them for that.

## Simple Web Utility BOF (Curl)

Beacon object file and associated aggressor to make simple web requests without establishing SOCKS PROXY. Example use case could be confirming outbound access to specific service before deploying a relay from [F-Secure's C3](https://github.com/FSecureLABS/C3).