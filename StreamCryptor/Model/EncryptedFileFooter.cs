using System;
using System.Linq;
using ProtoBuf;
using Sodium;
using StreamCryptor.Helper;

namespace StreamCryptor.Model
{
    /// <summary>
    ///     EncryptedFileFooter for every file.
    /// </summary>
    [ProtoContract]
    public class EncryptedFileFooter
    {
        private readonly byte[] _checksumFooterPrefix = {0x02};

        /// <summary>
        ///     Initialize the EncryptedFileFooter for decryption.
        /// </summary>
        public EncryptedFileFooter()
        {
            //do nothing
        }

        /// <summary>
        ///     Initialize the EncryptedFileFooter for encryption.
        /// </summary>
        /// <param name="nonceLength">The length of the footer nonces.</param>
        /// <param name="chunkNumber">The number of chunks in the file.</param>
        /// <param name="overallChunkLength">The overall length of the chunks.</param>
        /// <remarks>Used for encryption.</remarks>
        public EncryptedFileFooter(int nonceLength, int chunkNumber, long overallChunkLength)
        {
            FooterNonceLength = SodiumCore.GetRandomBytes(nonceLength);
            FooterNonceCount = SodiumCore.GetRandomBytes(nonceLength);
            ChunkCount = BitConverter.GetBytes(chunkNumber);
            OverallChunkLength = BitConverter.GetBytes(overallChunkLength);
        }

        /// <summary>
        ///     The chunk count of this file.
        /// </summary>
        [ProtoMember(1)]
        private byte[] ChunkCount { get; set; }

        /// <summary>
        ///     The length of all chunks.
        /// </summary>
        [ProtoMember(2)]
        private byte[] OverallChunkLength { get; set; }

        /// <summary>
        ///     The nonce to encrypt and decrypt the OverallChunkLength.
        /// </summary>
        [ProtoMember(3)]
        private byte[] FooterNonceLength { get; set; }

        /// <summary>
        ///     The nonce to encrypt and decrypt the ChunkCount.
        /// </summary>
        [ProtoMember(4)]
        private byte[] FooterNonceCount { get; set; }

        /// <summary>
        ///     The footer checksum to validate this footer.
        /// </summary>
        [ProtoMember(5)]
        private byte[] FooterChecksum { get; set; }

        /// <summary>
        ///     Sets the footer checksum.
        /// </summary>
        /// <param name="ephemeralKey">A 64 byte key.</param>
        /// <param name="footerChecksumLength">The length of the checksum.</param>
        public void SetFooterChecksum(byte[] ephemeralKey, int footerChecksumLength)
        {
            //protect the ChunkCount
            ChunkCount = SecretBox.Create(ChunkCount, FooterNonceCount, Utils.GetEphemeralEncryptionKey(ephemeralKey));
            //protect the OverallChunkLength
            OverallChunkLength = SecretBox.Create(OverallChunkLength, FooterNonceLength,
                Utils.GetEphemeralEncryptionKey(ephemeralKey));
            //generate and set the Footerchecksum
            FooterChecksum = ArrayHelpers.ConcatArrays(_checksumFooterPrefix,
                GenericHash.Hash(ArrayHelpers.ConcatArrays(ChunkCount, OverallChunkLength),
                    Utils.GetEphemeralHashKey(ephemeralKey), footerChecksumLength));
        }

        /// <summary>
        ///     Validates the footer checksum.
        /// </summary>
        /// <param name="chunkCount">Number of chunks in the file.</param>
        /// <param name="chunkOverallLength">Length of all chunks in the file.</param>
        /// <param name="ephemeralKey">A 64 byte key.</param>
        /// <param name="footerChecksumLength">The length of the checksum.</param>
        /// <exception cref="BadFileFooterException"></exception>
        public void ValidateFooterChecksum(byte[] chunkCount, byte[] chunkOverallLength, byte[] ephemeralKey,
            int footerChecksumLength)
        {
            var footerChecksum = ArrayHelpers.ConcatArrays(_checksumFooterPrefix, GenericHash.Hash(
                ArrayHelpers.ConcatArrays(
                    SecretBox.Create(chunkCount, FooterNonceCount, Utils.GetEphemeralEncryptionKey(ephemeralKey)),
                    SecretBox.Create(chunkOverallLength, FooterNonceLength,
                        Utils.GetEphemeralEncryptionKey(ephemeralKey))),
                Utils.GetEphemeralHashKey(ephemeralKey),
                footerChecksumLength));
            //check the file footer
            if (!footerChecksum.SequenceEqual(FooterChecksum))
            {
                throw new BadFileFooterException("Malformed file footer: file could be damaged or manipulated!");
            }
        }
    }
}