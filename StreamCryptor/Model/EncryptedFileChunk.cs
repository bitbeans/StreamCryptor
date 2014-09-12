using ProtoBuf;

namespace StreamCryptor.Model
{
    [ProtoContract]
    public class EncryptedFileChunk
    {
        [ProtoMember(1)]
        public long ChunkNumber { get; set; }
        [ProtoMember(2)]
        public byte[] ChunkNonce { get; set; }
        [ProtoMember(3)]
        public int ChunkLength { get; set; }
        [ProtoMember(4)]
        public bool ChunkIsLast { get; set; }
        [ProtoMember(5)]
        public byte[] ChunkChecksum { get; set; }
        [ProtoMember(6)]
        public byte[] Chunk { get; set; }
        
    }
}
