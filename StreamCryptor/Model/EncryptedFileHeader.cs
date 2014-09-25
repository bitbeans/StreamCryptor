using ProtoBuf;
using StreamCryptor.Helper;
using System;
using System.Linq;

namespace StreamCryptor.Model
{
    /// <summary>
    /// EncryptedFileHeader for every file.
    /// </summary>
    [ProtoContract]
    public class EncryptedFileHeader
    {
        /// <summary>
        /// Library version which the file was encrapted. 
        /// </summary>
        [ProtoMember(1)]
        public int Version { get; set; }
        /// <summary>
        /// The file length of the unencrypted file.
        /// </summary>
        [ProtoMember(2)]
        public long UnencryptedFileLength { get; set; }
        /// <summary>
        /// The base 16 byte base nonce.
        /// </summary>
        [ProtoMember(3)]
        public byte[] BaseNonce { get; set; }
        /// <summary>
        /// The 24 byte nonce for the ephemeral secret key.
        /// </summary>
        [ProtoMember(4)]
        public byte[] EphemeralNonce { get; set; }
        /// <summary>
        /// The 32 byte ephemeral secret key. 
        /// </summary>
        [ProtoMember(5)]
        public byte[] Key { get; set; }
        /// <summary>
        /// The header checksum to validate this header.
        /// </summary>
        [ProtoMember(6)]
        private byte[] HeaderChecksum { get; set; }
        /// <summary>
        /// Encrypted original filename.
        /// </summary>
        [ProtoMember(7)]
        public byte[] Filename { get; set; }
        /// <summary>
        /// The 24 byte nonce to encrypt the filename.
        /// </summary>
        [ProtoMember(8)]
        public byte[] FilenameNonce { get; set; }
        /// <summary>
        /// The 32 byte public key of the sender.
        /// </summary>
        [ProtoMember(9)]
        public byte[] SenderPublicKey { get; set; }

        /// <summary>
        /// Sets the header checksum.
        /// </summary>
        /// <param name="ephemeralKey">A 32 byte key.</param>
        /// <param name="headerChecksumLength">The length of the checksum.</param>
        public void SetHeaderChecksum(byte[] ephemeralKey, int headerChecksumLength)
        {
            this.HeaderChecksum = Sodium.GenericHash.Hash(
                ArrayHelpers.ConcatArrays(this.BaseNonce,
                Utils.IntegerToLittleEndian(this.Version),
                this.Key,
                BitConverter.GetBytes(this.UnencryptedFileLength)),
                ephemeralKey,
                headerChecksumLength);
        }

        /// <summary>
        /// Validates the header checksum.
        /// </summary>
        /// <param name="ephemeralKey">A 32 byte key.</param>
        /// <param name="headerChecksumLength">The length of the checksum.</param>
        /// <exception cref="BadFileHeaderException"></exception>
        public void ValidateHeaderChecksum(byte[] ephemeralKey, int headerChecksumLength)
        {
            byte[] headerChecksum = Sodium.GenericHash.Hash(
                ArrayHelpers.ConcatArrays(this.BaseNonce, 
                Utils.IntegerToLittleEndian(this.Version), 
                this.Key, 
                BitConverter.GetBytes(this.UnencryptedFileLength)), 
                ephemeralKey,
                headerChecksumLength);
            if (!headerChecksum.SequenceEqual(this.HeaderChecksum))
            {
                throw new BadFileHeaderException("Malformed file header: file could be damaged or manipulated!");
            }
        }
    }
}
