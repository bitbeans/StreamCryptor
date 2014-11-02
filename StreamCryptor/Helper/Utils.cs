using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace StreamCryptor.Helper
{
    public static class Utils
    {
        /// <summary>
        /// Converts an integer to a little endian byte array.
        /// </summary>
        /// <param name="data">An integer.</param>
        /// <returns>little endian byte array</returns>
        public static byte[] IntegerToLittleEndian(int data)
        {
            byte[] le = new byte[8];
            le[0] = (byte)data;
            le[1] = (byte)(((uint)data >> 8) & 0xFF);
            le[2] = (byte)(((uint)data >> 16) & 0xFF);
            le[3] = (byte)(((uint)data >> 24) & 0xFF);
            return le;
        }

        /// <summary>
        /// Returns a SHA256 file checksum.
        /// </summary>
        /// <param name="path">The full path.</param>
        /// <returns>SHA256 checksum without hyphens.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static string GetChecksum(string path)
        {
            if (path == null)
                throw new ArgumentNullException("path", "path can not be null");

            string checksum = "";
            using (System.IO.FileStream stream = System.IO.File.OpenRead(path))
            {
                System.Security.Cryptography.SHA256Managed sha = new System.Security.Cryptography.SHA256Managed();
                byte[] bytes = sha.ComputeHash(stream);
                checksum = BitConverter.ToString(bytes).Replace("-", String.Empty);
            }
            return checksum;
        }

        /// <summary>
        /// Returns a SHA256 byte[] checksum.
        /// </summary>
        /// <param name="path">The full path.</param>
        /// <returns>SHA256 checksum without hyphens.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static string GetChecksum(byte[] array)
        {
            if (array == null)
                throw new ArgumentNullException("array", "array can not be null");

            string checksum = "";
            using (System.IO.MemoryStream stream = new System.IO.MemoryStream(array))
            {
                System.Security.Cryptography.SHA256Managed sha = new System.Security.Cryptography.SHA256Managed();
                byte[] bytes = sha.ComputeHash(stream);
                checksum = BitConverter.ToString(bytes).Replace("-", String.Empty);
            }
            return checksum;
        }

        /// <summary>
        /// Generates random number.
        /// </summary>
        /// <param name="maxNumber">The max number.</param>
        /// <see cref="http://blog.codeeffects.com/Article/Generate-Random-Numbers-And-Strings-C-Sharp"/>
        /// <returns>A random number.</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static int GetRandomNumber(int maxNumber)
        {
            if (maxNumber < 1)
                throw new ArgumentOutOfRangeException("maxNumber", "maxNumber must be greater than 0");
            byte[] b = new byte[4];
            new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(b);
            int seed = (b[0] & 0x7f) << 24 | b[1] << 16 | b[2] << 8 | b[3];
            System.Random r = new System.Random(seed);
            return r.Next(1, maxNumber);
        }

        /// <summary>
        /// Generates a random string of given length.
        /// </summary>
        /// <param name="length">length of the random string.</param>
        /// <see cref="http://blog.codeeffects.com/Article/Generate-Random-Numbers-And-Strings-C-Sharp"/>
        /// <returns>A random string.</returns>
        public static string GetRandomString(int length)
        {
            string[] array = new string[54]
	        {
		        "0","2","3","4","5","6","8","9",
		        "a","b","c","d","e","f","g","h","j","k","m","n","p","q","r","s","t","u","v","w","x","y","z",
		        "A","B","C","D","E","F","G","H","J","K","L","M","N","P","R","S","T","U","V","W","X","Y","Z"
	        };
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < length; i++) sb.Append(array[GetRandomNumber(53)]);
            return sb.ToString();
        }

        /// <summary>
        /// Converts a string into a byte array and fill it up to given length.
        /// </summary>
        /// <param name="str">The input string.</param>
        /// <param name="paddingLength">The padding length.</param>
        /// <returns>A byte[256] array.</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static byte[] StringToPaddedByteArray(string str, int paddingLength)
        {
            if (str.Length > 256)
            {
                throw new ArgumentOutOfRangeException("str", "str must be <= 256 chars");
            }
            if (paddingLength > 256)
            {
                throw new ArgumentOutOfRangeException("paddingLength", "paddingLength must be <= 256");
            }
            return Encoding.UTF8.GetBytes(str.PadRight(paddingLength, '\0'));
        }

        /// <summary>
        /// Converts a padded byte array to a unpadded string.
        /// </summary>
        /// <param name="paddedByteArray">The padded byte array.</param>
        /// <returns>An unpadded string.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static string PaddedByteArrayToString(byte[] paddedByteArray)
        {
            if (paddedByteArray == null)
            {
                throw new ArgumentNullException("paddedByteArray", "paddedByteArray can not be null");
            }
            return Encoding.UTF8.GetString(paddedByteArray).TrimEnd('\0');
        }

        /// <summary>
        /// Determines if is mono runtime.
        /// </summary>
        /// <returns><c>true</c> if is mono runtime; otherwise, <c>false</c>.</returns>
        public static bool IsMonoRuntime()
        {
            return Type.GetType("Mono.Runtime") != null;
        }

        /// <summary>
        /// Is running on windows.
        /// </summary>
        /// <returns><c>true</c>, if on windows was runninged, <c>false</c> otherwise.</returns>
        public static bool IsRunningOnWindows()
        {
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                case PlatformID.Win32S:
                case PlatformID.Win32Windows:
                case PlatformID.WinCE:
                    return true;
                default:
                    return false;
            }
        }
    }
}
