using ProtoBuf;

namespace StreamCryptor.Model
{
    [ProtoContract]
    public class EncryptedFileHeader
    {
        [ProtoMember(1)]
        public int Version { get; set; }
        [ProtoMember(2)]
        public long UnencryptedFileLength { get; set; }
        [ProtoMember(3)]
        public byte[] BaseNonce { get; set; }
        [ProtoMember(4)]
        public byte[] Nonce { get; set; }
        [ProtoMember(5)]
        public byte[] Key { get; set; }
        [ProtoMember(6)]
        public byte[] Checksum { get; set; }
    }
}
