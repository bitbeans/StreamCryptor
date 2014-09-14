using ProtoBuf;

namespace StreamCryptor.Model
{
    /// <summary>
    /// EncryptedFileFooter for every file.
    /// </summary>
    [ProtoContract]
    public class EncryptedFileFooter
    {
        /// <summary>
        /// The chunk count of this file.
        /// </summary>
        [ProtoMember(1)]
        public byte[] ChunkCount { get; set; }
        /// <summary>
        /// The length of all chunks.
        /// </summary>
        [ProtoMember(2)]
        public byte[] OverallChunkLength { get; set; }
        /// <summary>
        /// The nonce to encrypt and decrypt the OverallChunkLength.
        /// </summary>
        [ProtoMember(3)]
        public byte[] FooterNonceLength { get; set; }
        /// <summary>
        /// The nonce to encrypt and decrypt the ChunkCount.
        /// </summary>
        [ProtoMember(4)]
        public byte[] FooterNonceCount { get; set; }
        /// <summary>
        /// The footer checksum to validate this footer.
        /// </summary>
        [ProtoMember(5)]
        public byte[] FooterChecksum { get; set; }
    }
}
