using ProtoBuf;
using Sodium;
using StreamCryptor.Helper;
using StreamCryptor.Model;
using System;
using System.IO;
using System.Linq;

namespace StreamCryptor
{
    /// <summary>
    /// Class to encrypt and decrypt files in a stream.
    /// Using: libsodium and protobuf-net.
    /// </summary>
    public static class StreamCryptor
    {
        private const int CHUNK_LENGTH = 1048576; //~1MB
        private const int CHUNK_COUNT_START = 0;
        private const int NONCE_LENGTH = 24;
        private const int BASE_NONCE_LENGTH = 16;
        private const int CURRENT_VERSION = 1;
        private const int MIN_VERSION = 1;

        /// <summary>
        /// Generates an accumulated nonce.
        /// </summary>
        /// <param name="baseNonce">16 byte nonce.</param>
        /// <param name="chunkNumber">Number to accumulate.</param>
        /// <param name="isLastChunkInStream">Idicates if this chunk is the last in the stream.</param>
        /// <returns></returns>
        public static byte[] GetChunkNonce(byte[] baseNonce, int chunkNumber, bool isLastChunkInStream = false)
        {
            //TODO: validate input
            byte[] chunkNumberAsByte = Utils.IntegerToLittleEndian(chunkNumber);
            byte[] concatNonce = ArrayHelpers.ConcatArrays(baseNonce, chunkNumberAsByte);
            //set last part to 128
            if (isLastChunkInStream)
                concatNonce[23] |= 0x80;

            return concatNonce;
        }

        /// <summary>
        /// Encrypts a file with libsodium and protobuf-net.
        /// </summary>
        /// <param name="keyPair">A KeyPair to encrypt the ephemeralKey.</param>
        /// <param name="inputFile">A raw file.</param>
        /// <param name="outputFile">There the encrypted file will be stored.</param>
        public static void EncryptFileWithStream(KeyPair keyPair, string inputFile, string outputFile)
        {
            //TODO: validate input
            //go for the streams
            using (FileStream fileStreamEncrypted = File.OpenWrite(outputFile))
            {
                using (FileStream fileStreamUnencrypted = File.OpenRead(inputFile))
                {
                    //prepare our file header
                    EncryptedFileHeader encryptedFileHeader = new EncryptedFileHeader();
                    
                    //get some ephemeral key fot this file
                    byte[] ephemeralKey = SecretBox.GenerateKey();
                    //generate a nonce for the encrypted ephemeral key
                    byte[] nonce = Sodium.SodiumCore.GetRandomBytes(NONCE_LENGTH);
                    //encrypt the ephemeral key with our public box 
                    byte[] encryptedEphemeralKey = Sodium.PublicKeyBox.Create(ephemeralKey, nonce, keyPair.PrivateKey, keyPair.PublicKey);

                    long fileLength = fileStreamUnencrypted.Length;
                    int chunkNumber = CHUNK_COUNT_START;
                    //set some things to the file header
                    encryptedFileHeader.UnencryptedFileLength = fileLength;
                    encryptedFileHeader.Version = CURRENT_VERSION;
                    //a random base nonce, which will be filled up to 24 byte with every chunk
                    encryptedFileHeader.BaseNonce = SodiumCore.GetRandomBytes(BASE_NONCE_LENGTH);
                    encryptedFileHeader.Nonce = nonce;
                    encryptedFileHeader.Key = encryptedEphemeralKey;
                    encryptedFileHeader.Checksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedFileHeader.BaseNonce, Utils.IntegerToLittleEndian(encryptedFileHeader.Version), encryptedFileHeader.Key), ephemeralKey, 64);
                    //TODO: extend header class and don`t set garbage! :P
                    //- baseNonce, file length, checksum, encrypted ephemeralKey, mac, maybe more data if the filename was encrypted ....

                    //write the file header
                    Serializer.SerializeWithLengthPrefix(fileStreamEncrypted, encryptedFileHeader, PrefixStyle.Fixed32, 1);
                    //start reading the unencrypted file in chunks of the given length: CHUNK_LENGTH
                    byte[] unencryptedChunk = new byte[CHUNK_LENGTH];
                    int bytesRead;
                    do
                    {
                        byte[] chunkNonce = new byte[NONCE_LENGTH];
                        bytesRead = fileStreamUnencrypted.Read(unencryptedChunk, 0, CHUNK_LENGTH);
                        //check if there is still some work
                        if (bytesRead != 0)
                        {
                            //prepare the EncryptedFileChunk
                            EncryptedFileChunk encryptedFileChunk = new EncryptedFileChunk();
                            byte[] readedBytes = new byte[bytesRead];
                            //FIXME: maybe there is a better solution
                            //cut unreaded bytes
                            Array.Copy(unencryptedChunk, readedBytes, bytesRead);
                            //check if the file is smaller or equal the CHUNK_LENGTH
                            if (fileLength <= CHUNK_LENGTH)
                            {
                                //so we have the one and only chunk
                                chunkNonce = GetChunkNonce(encryptedFileHeader.BaseNonce, chunkNumber, true);
                                encryptedFileChunk.ChunkIsLast = true;
                            }
                            else
                            {
                                //let`s check if this chunk is smaller than the given CHUNK_LENGTH
                                if (bytesRead < CHUNK_LENGTH)
                                {
                                    //it`s the last chunk in the stream
                                    chunkNonce = GetChunkNonce(encryptedFileHeader.BaseNonce, chunkNumber, true);
                                    encryptedFileChunk.ChunkIsLast = true;
                                }
                                else
                                {
                                    //it`s a full chunk
                                    chunkNonce = GetChunkNonce(encryptedFileHeader.BaseNonce, chunkNumber, false);
                                    encryptedFileChunk.ChunkIsLast = false;
                                }
                            }
                            //we also set the current chunk number to validate the nonce later
                            encryptedFileChunk.ChunkNumber = chunkNumber;
                            //set the chunk nonce (it containes the chunkNumber too)
                            encryptedFileChunk.ChunkNonce = chunkNonce;
                            //sym encrypt the chunk 
                            byte[] encryptedChunk = SecretBox.Create(readedBytes, chunkNonce, ephemeralKey);
                            //set the encrypted chunk
                            encryptedFileChunk.Chunk = encryptedChunk;
                            //and also the length of it
                            encryptedFileChunk.ChunkLength = encryptedChunk.Length;
                            //generate a 64 byte checksum for this chunk
                            encryptedFileChunk.ChunkChecksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedChunk, Utils.IntegerToLittleEndian(encryptedChunk.Length), chunkNonce), ephemeralKey, 64);
                            //write encryptedFileChunk to the output stream
                            Serializer.SerializeWithLengthPrefix(fileStreamEncrypted, encryptedFileChunk, PrefixStyle.Fixed32, 1);
                            //increment for the next chunk
                            chunkNumber++;
                        }
                    } while (bytesRead != 0);
                }
            }
        }

        /// <summary>
        /// Decrypts a file with libsodium and protobuf-net.
        /// </summary>
        /// <param name="keyPair">A KeyPair to decrypt the ephemeralKey.</param>
        /// <param name="inputFile">An encrypted file.</param>
        /// <param name="outputFile">There the decrypted file will be stored.</param>
        public static void DecryptFileWithStream(KeyPair keyPair, string inputFile, string outputFile)
        {
            //TODO: validate input
            using (FileStream fileStreamUnencrypted = File.OpenWrite(outputFile))
            {
                using (FileStream fileStreamEncrypted = File.OpenRead(inputFile))
                {
                    int chunkNumber = CHUNK_COUNT_START;
                    //first read the file header
                    EncryptedFileHeader encryptedFileHeader = new EncryptedFileHeader();
                    encryptedFileHeader = Serializer.DeserializeWithLengthPrefix<EncryptedFileHeader>(fileStreamEncrypted, PrefixStyle.Fixed32, 1);

                    //decrypt the ephemeral key with our public box 
                    byte[] ephemeralKey = Sodium.PublicKeyBox.Open(encryptedFileHeader.Key, encryptedFileHeader.Nonce, keyPair.PublicKey, keyPair.PrivateKey);
                    byte[] headerChecksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedFileHeader.BaseNonce, Utils.IntegerToLittleEndian(encryptedFileHeader.Version), encryptedFileHeader.Key), ephemeralKey, 64);
                    //check file header
                    if ((encryptedFileHeader.Version >= MIN_VERSION) &&
                        (encryptedFileHeader.BaseNonce.Length == BASE_NONCE_LENGTH) &&
                        (encryptedFileHeader.Checksum.SequenceEqual(headerChecksum))) 
                    {
                        //start reading the chunks
                        EncryptedFileChunk encryptedFileChunk = new EncryptedFileChunk();
                        while ((encryptedFileChunk = Serializer.DeserializeWithLengthPrefix<EncryptedFileChunk>(fileStreamEncrypted, PrefixStyle.Fixed32, 1)) != null)
                        {
                            byte[] chunkNonce = new byte[NONCE_LENGTH];
                            //check if this is the last chunk
                            if (encryptedFileChunk.ChunkIsLast)
                            {
                                //last
                                chunkNonce = GetChunkNonce(encryptedFileHeader.BaseNonce, chunkNumber, true);
                            }
                            else
                            {
                                //there will propably come more
                                chunkNonce = GetChunkNonce(encryptedFileHeader.BaseNonce, chunkNumber, false);
                            }
                            //generate chunk checksum

                            byte[] chunkChecksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedFileChunk.Chunk, Utils.IntegerToLittleEndian(encryptedFileChunk.Chunk.Length), chunkNonce), ephemeralKey, 64);
                            //check the current chunk checksum
                            if (chunkChecksum.SequenceEqual(encryptedFileChunk.ChunkChecksum))
                            {
                                byte[] decrypted = SecretBox.Open(encryptedFileChunk.Chunk, chunkNonce, ephemeralKey);
                                fileStreamUnencrypted.Write(decrypted, 0, decrypted.Length);
                            }
                            else
                            {
                                throw new Exception("bad chunk");
                            }
                            chunkNumber++;
                        }
                    }
                    else
                    {
                        throw new Exception("bad file header");
                    }
                }
            }
        }
    }
}
