# Beacon Object Files

| Name                                         | Syntax                 | 
| -------------------------------------------- | ---------------------- | 
| ETW Patching                                 | `etw stop` / `etw start`   | 
| API Function Utility                         | `read_function` / `check_function` / `patch_function <dll_path> <function_name>` | 
| Syscalls Shellcode Injection                 | `syscalls_inject <PID> <listener_name>` / `syscalls_shinject <PID> <path_to_bin>` | 
| Spawn and Syscalls Shellcode Injection       | `syscalls_spawn <PID> <listener>` / `syscalls_shspawn <PID> <path_to_bin>` | 
| Static Syscalls Shellcode Injection          | `static_syscalls_inject <PID> <listener_name>` / `static_syscalls_shinject <PID> <path_to_bin>` | 
| Static Syscalls Process Dump                 | `static_syscalls_dump <PID> [path_to_output]` | 



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

## Static Syscalls Shellcode Injection BOF (64-bit only)

Beacon object file to:
- Inject shellcode (either custom or beacon) into remote process using NtOpenProcess -> NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtCreateThreadEx.

Same injection process as above, but using static Syscalls, rather than stubs fetched from Ntdll.

Syscalls generated using @jthuraisamy's [SysWhispers](https://github.com/jthuraisamy/SysWhispers) and @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

## Static Syscalls Process Dump BOF (64-bit only)

Beacon object file to:
- Unhook NtReadVirtualMemory function.
- Create process memory dump using MiniDumpWriteDump function to specified (or default) location

Syscalls generated using @jthuraisamy's [SysWhispers](https://github.com/jthuraisamy/SysWhispers) and @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

This is effectively a rough port of @Outflank's [Dumpert](https://github.com/outflanknl/Dumpert) tool. All credit to them for that.