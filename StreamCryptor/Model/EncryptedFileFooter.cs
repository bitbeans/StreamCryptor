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
        ///     The footer checksum to validate this footer.
        /// </summary>
        [ProtoMember(1)]
        private byte[] FooterChecksum { get; set; }

        /// <summary>
        ///     Sets the footer checksum.
        /// </summary>
        /// <param name="chunkCount">Number of chunks in the file.</param>
        /// <param name="chunkOverallLength">Length of all chunks in the file.</param>
        /// <param name="ephemeralKey">A 64 byte key.</param>
        /// <param name="footerChecksumLength">The length of the checksum.</param>
        public void SetFooterChecksum(byte[] chunkCount, byte[] chunkOverallLength, byte[] ephemeralKey,
            int footerChecksumLength)
        {
            //generate and set the Footerchecksum
            FooterChecksum = GenericHash.Hash(ArrayHelpers.ConcatArrays(_checksumFooterPrefix,
                chunkCount, chunkOverallLength),
                Utils.GetEphemeralHashKey(ephemeralKey), footerChecksumLength);
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
            var footerChecksum = GenericHash.Hash(
                ArrayHelpers.ConcatArrays(_checksumFooterPrefix, chunkCount, chunkOverallLength),
                Utils.GetEphemeralHashKey(ephemeralKey),
                footerChecksumLength);
            //check the file footer
            if (!footerChecksum.SequenceEqual(FooterChecksum))
            {
                throw new BadFileFooterException("Malformed file footer: file could be damaged or manipulated!");
            }
        }
    }
}