## ETW Patching BOF

Simple Beacon object file to patch (and revert) the EtwEventWrite function in ntdll.dll to degrade ETW based logging.

All credit goes to @xpn: https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/.

## Compile

```
x86_64-w64-mingw32-gcc -c etw.c -o etw.x64.o
i686-w64-mingw32-gcc -c etw.c -o etw.x86.o
```

## Usage

Aggressor script included with `etw start` and `etw stop` commands.

Patch bytes returned to confirm activity.

```
beacon> help etw
etw stop - patch out EtwEventWrite in Ntdll.dll to prevent ETW-based logging.
etw start - patch back in EtwEventWrite in Ntdll.dll to restart ETW-based logging.

beacon> etw stop
[*] Running ETW patching BOF (@ajpc500)
[+] host called home, sent: 1391 bytes
[+] received output:
Action: stop
Working with 32-bit.
[+] received output:
c2
[+] received output:
14
[+] received output:
0
[+] received output:
0
```