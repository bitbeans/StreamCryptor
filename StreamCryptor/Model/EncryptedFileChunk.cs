using ProtoBuf;

namespace StreamCryptor.Model
{
    /// <summary>
    /// EncryptedFileChunk which every file contains.
    /// </summary>
    [ProtoContract]
    public class EncryptedFileChunk
    {
        /// <summary>
        /// Chunk number, starting at 0.
        /// </summary>
        [ProtoMember(1)]
        public long ChunkNumber { get; set; }
        /// <summary>
        /// Combined chunk nonce (16 byte BaseNonce||8 byte ChunkNumber)
        /// </summary>
        [ProtoMember(2)]
        public byte[] ChunkNonce { get; set; }
        /// <summary>
        /// The length of the current chunk in bytes.
        /// </summary>
        [ProtoMember(3)]
        public int ChunkLength { get; set; }
        /// <summary>
        /// Marks this chunk as last in the file.
        /// </summary>
        [ProtoMember(4)]
        public bool ChunkIsLast { get; set; }
        /// <summary>
        /// A checksum to validate this chunk.
        /// </summary>
        [ProtoMember(5)]
        public byte[] ChunkChecksum { get; set; }
        /// <summary>
        /// The chunk content.
        /// </summary>
        [ProtoMember(6)]
        public byte[] Chunk { get; set; }
        
    }
}
