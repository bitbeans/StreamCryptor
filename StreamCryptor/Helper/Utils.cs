using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace StreamCryptor.Helper
{
    public static class Utils
    {
        private const int EPHEMERAL_KEY_BYTES = 64;

        /// <summary>
        ///     Extract the encryption key from the ephemeralKey.
        /// </summary>
        /// <param name="ephemeralKey">The 64 byte ephemeralKey.</param>
        /// <returns>Returns a byte array with 32 bytes.</returns>
        /// <exception cref="ArgumentOutOfRangeException">ephemeralKey</exception>
        public static byte[] GetEphemeralEncryptionKey(byte[] ephemeralKey)
        {
            if (ephemeralKey == null || ephemeralKey.Length != EPHEMERAL_KEY_BYTES)
                throw new ArgumentOutOfRangeException("ephemeralKey", (ephemeralKey == null) ? 0 : ephemeralKey.Length,
                    string.Format("ephemeralKey must be {0} bytes in length.", EPHEMERAL_KEY_BYTES));

            return ArrayHelpers.SubArray(ephemeralKey, 0, 32);
        }

        /// <summary>
        ///     Extract the hash key from the ephemeralKey.
        /// </summary>
        /// <param name="ephemeralKey">The 64 byte ephemeralKey.</param>
        /// <returns>Returns a byte array with 32 bytes.</returns>
        /// <exception cref="ArgumentOutOfRangeException">ephemeralKey</exception>
        public static byte[] GetEphemeralHashKey(byte[] ephemeralKey)
        {
            if (ephemeralKey == null || ephemeralKey.Length != EPHEMERAL_KEY_BYTES)
                throw new ArgumentOutOfRangeException("ephemeralKey", (ephemeralKey == null) ? 0 : ephemeralKey.Length,
                    string.Format("ephemeralKey must be {0} bytes in length.", EPHEMERAL_KEY_BYTES));

            return ArrayHelpers.SubArray(ephemeralKey, 32);
        }

        /// <summary>
        ///     Converts an integer to a little endian byte array.
        /// </summary>
        /// <param name="data">An integer.</param>
        /// <returns>little endian byte array</returns>
        public static byte[] IntegerToLittleEndian(int data)
        {
            var le = new byte[8];
            le[0] = (byte) data;
            le[1] = (byte) (((uint) data >> 8) & 0xFF);
            le[2] = (byte) (((uint) data >> 16) & 0xFF);
            le[3] = (byte) (((uint) data >> 24) & 0xFF);
            return le;
        }

        /// <summary>
        ///     Returns a SHA256 file checksum.
        /// </summary>
        /// <param name="path">The full path.</param>
        /// <returns>SHA256 checksum without hyphens.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static string GetChecksum(string path)
        {
            if (path == null)
                throw new ArgumentNullException("path", "path can not be null");

            var checksum = "";
            using (var stream = File.OpenRead(path))
            {
                var sha = new SHA256Managed();
                var bytes = sha.ComputeHash(stream);
                checksum = BitConverter.ToString(bytes).Replace("-", String.Empty);
            }
            return checksum;
        }

        /// <summary>
        ///     Returns a SHA256 byte[] checksum.
        /// </summary>
        /// <param name="array">A byte array.</param>
        /// <returns>SHA256 checksum without hyphens.</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        public static string GetChecksum(byte[] array)
        {
            if (array == null)
                throw new ArgumentNullException("array", "array can not be null");

            var checksum = "";
            using (var stream = new MemoryStream(array))
            {
                var sha256 = new SHA256Managed();
                var bytes = sha256.ComputeHash(stream);
                checksum = BitConverter.ToString(bytes).Replace("-", String.Empty);
            }
            return checksum;
        }

        /// <summary>
        ///     Generates random number.
        /// </summary>
        /// <param name="maxNumber">The max number.</param>
        /// <returns>A random number.</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <remarks>Move to libsodium-net: waiting for stable release</remarks>
        public static int GetRandomNumber(int maxNumber)
        {
            if (maxNumber < 1) {
                throw new ArgumentOutOfRangeException("maxNumber", "maxNumber must be greater than 0");
            }
            
            // Get the number of bits needed to store this number
            var numBits = Convert.ToInt32(
                Math.Ceiling(Math.Log(maxNumber, 2))
            );
            
            // Get the number of bytes
            var numBytes = Convert.ToInt32(
                Math.Ceiling(numBits / 8)
            );
            
            // 2^N - 1 builds a binary mask for use with the & bitwise operator
            var mask = Convert.ToInt32(
                Math.Pow(2, numBits)
            ) - 1;
            
            var rval = 0;
            var b = new byte[numBytes];
            do {
                // Let's get our bytes
                new RNGCryptoServiceProvider().GetBytes(b);
                
                rval = 0;
                for (var i = 0; i < numBytes; i++) {
                    rval |= b[i] << (i * 8);
                }
                
                // Apply the bit mask
                rval &= mask;
            } while (rval >= maxNumber);
            
            // We now have an integer between 0 and maxNumber (non-inclusive)
            return rval;
        }

        /// <summary>
        ///     Generates a random string of given length.
        /// </summary>
        /// <param name="length">length of the random string.</param>
        /// <returns>A random string.</returns>
        /// <remarks>Move to libsodium-net: waiting for stable release</remarks>
        public static string GetRandomString(int length)
        {
            var array = new string[54]
            {
                "0", "2", "3", "4", "5", "6", "8", "9",
                "a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "m", "n", "p", "q", "r", "s", "t", "u", "v", "w", "x",
                "y", "z",
                "A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "L", "M", "N", "P", "R", "S", "T", "U", "V", "W", "X",
                "Y", "Z"
            };
            var sb = new StringBuilder();
            for (var i = 0; i < length; i++) sb.Append(array[GetRandomNumber(array.Length)]);
            return sb.ToString();
        }

        /// <summary>
        ///     Converts a string into a byte array and fill it up to given length.
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
        ///     Converts a padded byte array to a unpadded string.
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
    }
}
