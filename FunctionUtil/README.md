## API Function Utility BOF

Beacon object file to:
	- Read bytes of loaded module API function
	- Read relevant on-disk DLL and compare functions to identify differencies (e.g. EPP/EDR hooking)
	- Patch functions with the on-disk copy (i.e. API unhooking)

Credit goes to @spotheplanet for the Dll parsing technique: https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time

## Compile

```
make all
```

## Usage

Aggressor script included with the following commands:
	- `read_function` - Output the first 8 bytes of the specified function(s) and output the bytes to the console.
	- `check_function` - Parse the on-disk DLL containing the specified function(s) and confirm the first 8 bytes match. 
	- `patch_function` - As above, but patching the loaded function(s) with the on-disk bytes.

All three utilities can take multiple functions within the same DLL (see `read_function` usage below, as an example)

> NOTE: `check_function` and `patch_function` will only read on-disk DLL once when multiple functions are specified.

### Read Function

```
beacon> read_function ntdll.dll NtCreateProcess
[*] Running API Function Utility (@ajpc500)
[+] host called home, sent: 5116 bytes
[+] received output:
[*] Reading 8 bytes of NtCreateProcess function in ntdll.dll
[+] received output:
b8 b3 0
0 0 ba 70 71


beacon> read_function ntdll.dll NtCreateProcess,NtCreateFile
[*] Running API Function Utility (@ajpc500)
[+] host called home, sent: 5129 bytes
[+] received output:
[*] Reading 8 bytes of NtCreateProcess function in ntdll.dll
[+] received output:
b8 b3 0
0 0 ba 70 71
[+] received output:
[*] Reading 8 bytes of NtCreateFile function in ntdll.dll
[+] received output:
b8 55 0
0 0 ba 70 71
```

### Check Function

Demonstrating with ETW BOF: https://github.com/ajpc500/BOFs/tree/main/ETW

```
beacon> check_function ntdll.dll EtwEventWrite
[*] Running API Function Utility (@ajpc500)
[+] host called home, sent: 5558 bytes
[+] received output:
[+] EtwEventWrite function matches on-disk.

beacon> etw stop
[*] Running ETW patching BOF (@ajpc500)
[+] host called home, sent: 1439 bytes
[+] received output:
Action: stop
Working with 64-bit.
[+] received output:
c3

beacon> check_function ntdll.dll EtwEventWrite
[*] Running API Function Utility (@ajpc500)
[+] host called home, sent: 4727 bytes
[+] received output:
[*] Comparing 8 bytes of EtwEventWrite function(s) in ntdll.dll with on-disk version
[+] received output:
[!] EtwEventWrite function doesn't match on-disk.
[+] received output:
Loaded Module: c3 8b dc 48 83 ec 58 4d
Ondisk Module: 4c 8b dc 48 83 ec 58 4d
```

### Patch Function
```
beacon> check_function ntdll.dll EtwEventWrite
[*] Running API Function Utility (@ajpc500)
[+] host called home, sent: 4727 bytes
[+] received output:
[*] Comparing 8 bytes of EtwEventWrite function(s) in ntdll.dll with on-disk version
[+] received output:
[!] EtwEventWrite function doesn't match on-disk.
[+] received output:
Loaded Module: c3 8b dc 48 83 ec 58 4d
Ondisk Module: 4c 8b dc 48 83 ec 58 4d

beacon> patch_function ntdll.dll EtwEventWrite
[*] Running API Function Utility (@ajpc500)
[+] host called home, sent: 5558 bytes
[+] received output:
[*] Patching 8 bytes of EtwEventWrite function in ntdll.dll with on-disk version
[+] received output:
[+] Patched EtwEventWrite function successfully.

beacon> check_function ntdll.dll EtwEventWrite
[*] Running API Function Utility (@ajpc500)
[+] host called home, sent: 4727 bytes
[+] received output:
[*] Comparing 8 bytes of EtwEventWrite function(s) in ntdll.dll with on-disk version
[+] received output:
[+] EtwEventWrite function matches on-disk.
```
