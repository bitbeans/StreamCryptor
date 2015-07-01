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
        ///     Generates a random filename of given length.
        /// </summary>
        /// <param name="length">length of the random string.</param>
        /// <param name="fileExtension">a file extension</param>
        /// <returns>A random filename.</returns>
        /// <exception cref="FormatException">A file extension must start with: .</exception>
        public static string GetRandomFileName(int length, string fileExtension)
        {
            if (!fileExtension.StartsWith("."))
                throw new FormatException("A file extension must start with: .");
            var array = new string[54]
            {
                "0", "2", "3", "4", "5", "6", "8", "9",
                "a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "m", "n", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                "A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "L", "M", "N", "P", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"
            };
            var sb = new StringBuilder();
            for (var i = 0; i < length; i++) sb.Append(array[Sodium.SodiumCore.GetRandomNumber(array.Length)]);
            sb.Append(fileExtension);
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