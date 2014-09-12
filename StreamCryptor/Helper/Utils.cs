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
    }
}
