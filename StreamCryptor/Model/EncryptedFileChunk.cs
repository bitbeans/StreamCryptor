using System.Linq;
using ProtoBuf;
using Sodium;
using StreamCryptor.Helper;

namespace StreamCryptor.Model
{
    /// <summary>
    ///     EncryptedFileChunk which every file contains.
    /// </summary>
    [ProtoContract]
    public class EncryptedFileChunk
    {
        private readonly byte[] _checksumChunkPrefix = {0x01};

        /// <summary>
        ///     The length of the current chunk in bytes.
        /// </summary>
        [ProtoMember(1)]
        public int ChunkLength { get; set; }

        /// <summary>
        ///     Marks this chunk as last in the file.
        /// </summary>
        [ProtoMember(2)]
        public bool ChunkIsLast { get; set; }

        /// <summary>
        ///     A checksum to validate this chunk.
        /// </summary>
        [ProtoMember(3)]
        public byte[] ChunkChecksum { get; private set; }

        /// <summary>
        ///     The chunk content.
        /// </summary>
        [ProtoMember(4)]
        public byte[] Chunk { get; set; }

        /// <summary>
        ///     Sets the chunk checksum.
        /// </summary>
        /// <param name="ephemeralKey">A 64 byte key.</param>
        /// <param name="chunkChecksumLength">The length of the checksum.</param>
        public void SetChunkChecksum(byte[] ephemeralKey, int chunkChecksumLength)
        {
            ChunkChecksum = GenericHash.Hash(ArrayHelpers.ConcatArrays(_checksumChunkPrefix, Chunk,
                Utils.IntegerToLittleEndian(ChunkLength)),
                Utils.GetEphemeralHashKey(ephemeralKey), chunkChecksumLength);
        }

        /// <summary>
        ///     Validates the chunk checksum.
        /// </summary>
        /// <param name="ephemeralKey">A 64 byte key.</param>
        /// <param name="chunkChecksumLength">The length of the checksum.</param>
        /// <exception cref="BadFileChunkException"></exception>
        public void ValidateChunkChecksum(byte[] ephemeralKey, int chunkChecksumLength)
        {
            var chunkChecksum = GenericHash.Hash(
                ArrayHelpers.ConcatArrays(_checksumChunkPrefix, Chunk, Utils.IntegerToLittleEndian(ChunkLength)),
                Utils.GetEphemeralHashKey(ephemeralKey), chunkChecksumLength);
            if (!chunkChecksum.SequenceEqual(ChunkChecksum))
            {
                throw new BadFileChunkException("Wrong checksum, file could be damaged or manipulated!");
            }
        }
    }
}