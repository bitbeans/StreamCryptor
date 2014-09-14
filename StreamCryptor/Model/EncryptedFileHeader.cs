using ProtoBuf;

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
        public byte[] HeaderChecksum { get; set; }
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
    }
}
