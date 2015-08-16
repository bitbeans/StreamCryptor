using System;
using System.Linq;
using System.Text;
using ProtoBuf;
using Sodium;
using StreamCryptor.Helper;

namespace StreamCryptor.Model
{
    /// <summary>
    ///     EncryptedFileHeader for every file.
    /// </summary>
    [ProtoContract]
    public class EncryptedFileHeader
    {
        private readonly byte[] _checksumHeaderPrefix = {0x00};

        /// <summary>
        ///     Initialize the EncryptedFileHeader for decryption.
        /// </summary>
        /// <remarks>Used for decryption.</remarks>
        public EncryptedFileHeader()
        {
            //do nothing
        }

        /// <summary>
        ///     Initialize the EncryptedFileHeader for encryption.
        /// </summary>
        /// <param name="currentVersion">The StreamCryptor version.</param>
        /// <param name="nonceLength">The length which nonces will be generated.</param>
        /// <param name="chunkBaseNonceLength">The length of the base nonce.</param>
        /// <param name="unencryptedFileLength">The length of unencrypted file.</param>
        /// <param name="senderPrivateKey">The senders private key.</param>
        /// <param name="senderPublicKey">The senders public key.</param>
        /// <param name="recipientPublicKey">The recipient public key.</param>
        public EncryptedFileHeader(int currentVersion, int nonceLength, int chunkBaseNonceLength,
            long unencryptedFileLength, byte[] senderPrivateKey, byte[] senderPublicKey, byte[] recipientPublicKey)
        {
            //set the version
            Version = currentVersion;
            //get some ephemeral key fot this file
            UnencryptedEphemeralKey = SodiumCore.GetRandomBytes(64);
            //generate a nonce for the encrypted ephemeral key
            EphemeralNonce = SodiumCore.GetRandomBytes(nonceLength);
            //generate a nonce for encypting the file name
            FilenameNonce = SodiumCore.GetRandomBytes(nonceLength);
            //encrypt the ephemeral key with our public box 
            Key = PublicKeyBox.Create(UnencryptedEphemeralKey, EphemeralNonce, senderPrivateKey, recipientPublicKey);
            //set the senders public key to the header, to guarantee the recipient can decrypt it
            SenderPublicKey = senderPublicKey;
            //a random base nonce (16 byte), which will be filled up to 24 byte in every chunk
            BaseNonce = SodiumCore.GetRandomBytes(chunkBaseNonceLength);
            //set unencrypted file length to the file header
            UnencryptedFileLength = unencryptedFileLength;
        }

        /// <summary>
        ///     Library version which the file was encrypted.
        /// </summary>
        [ProtoMember(1)]
        public int Version { get; private set; }

        /// <summary>
        ///     The file length of the unencrypted file.
        /// </summary>
        [ProtoMember(2)]
        public long UnencryptedFileLength { get; private set; }

        /// <summary>
        ///     The base 16 byte base nonce.
        /// </summary>
        [ProtoMember(3)]
        public byte[] BaseNonce { get; private set; }

        /// <summary>
        ///     The 24 byte nonce for the ephemeral secret key.
        /// </summary>
        [ProtoMember(4)]
        public byte[] EphemeralNonce { get; private set; }

        /// <summary>
        ///     The 64 byte ephemeral secret key.
        /// </summary>
        [ProtoMember(5)]
        public byte[] Key { get; private set; }

        /// <summary>
        ///     The header checksum to validate this header.
        /// </summary>
        [ProtoMember(6)]
        private byte[] HeaderChecksum { get; set; }

        /// <summary>
        ///     Encrypted original filename.
        /// </summary>
        [ProtoMember(7)]
        public byte[] Filename { get; private set; }

        /// <summary>
        ///     The 24 byte nonce to encrypt the filename.
        /// </summary>
        [ProtoMember(8)]
        public byte[] FilenameNonce { get; private set; }

        /// <summary>
        ///     The 32 byte public key of the sender.
        /// </summary>
        [ProtoMember(9)]
        public byte[] SenderPublicKey { get; set; }

        /// <summary>
        ///     Storage for the EphemeralKey, will not be serialized.
        /// </summary>
        public byte[] UnencryptedEphemeralKey { get; private set; }

        /// <summary>
        ///     Encrypts the file name.
        /// </summary>
        /// <param name="fileName">The file name.</param>
        /// <param name="fileNameLength">The length it will be filled up.</param>
        /// <exception cref="OverflowException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public void ProtectFileName(string fileName, int fileNameLength)
        {
            //fill up the filename to 256 bytes
            var paddedFileName = Utils.AddPkcs7Padding(Encoding.UTF8.GetBytes(fileName), fileNameLength);
            //encrypt the file name in the header
            Filename = SecretBox.Create(paddedFileName, FilenameNonce,
                Utils.GetEphemeralEncryptionKey(UnencryptedEphemeralKey));
        }

        /// <summary>
        ///     Sets the header checksum.
        /// </summary>
        /// <param name="headerChecksumLength">The length of the checksum.</param>
        /// <exception cref="OverflowException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public void SetHeaderChecksum(int headerChecksumLength)
        {
            HeaderChecksum = GenericHash.Hash(ArrayHelpers.ConcatArrays(_checksumHeaderPrefix, BaseNonce,
                FilenameNonce, Filename,
                Utils.IntegerToLittleEndian(Version),
                Key,
                BitConverter.GetBytes(UnencryptedFileLength)),
                Utils.GetEphemeralHashKey(UnencryptedEphemeralKey),
                headerChecksumLength);
        }

        /// <summary>
        ///     Validates the header checksum.
        /// </summary>
        /// <param name="ephemeralKey">A 64 byte key.</param>
        /// <param name="headerChecksumLength">The length of the checksum.</param>
        /// <exception cref="BadFileHeaderException"></exception>
        public void ValidateHeaderChecksum(byte[] ephemeralKey, int headerChecksumLength)
        {
            var headerChecksum = GenericHash.Hash(
                ArrayHelpers.ConcatArrays(_checksumHeaderPrefix, BaseNonce,
                    FilenameNonce, Filename,
                    Utils.IntegerToLittleEndian(Version),
                    Key,
                    BitConverter.GetBytes(UnencryptedFileLength)),
                Utils.GetEphemeralHashKey(ephemeralKey),
                headerChecksumLength);
            if (!headerChecksum.SequenceEqual(HeaderChecksum))
            {
                throw new BadFileHeaderException("Malformed file header: file could be damaged or manipulated!");
            }
        }
    }
}