using ProtoBuf;
using Sodium;
using StreamCryptor.Helper;
using StreamCryptor.Model;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace StreamCryptor
{
    /// <summary>
    /// Class to encrypt and decrypt files in a stream.
    /// Using: libsodium and protobuf-net.
    /// </summary>
    public static class StreamCryptor
    {
        //TODO: 
        // - check filename length
        // - mask filename (maybe change outputFile to outputFolder and add the DEFAULT_FILE_EXTENSION)
        // - progress reporting 
        // - overloaded versions for more than one file
        // - version check (maybe implement protobuf versions)
        // - more tests
        private const int CHUNK_LENGTH = 1048576; //~1MB
        private const int CHUNK_COUNT_START = 0;
        private const int CHUNK_CHECKSUM_LENGTH = 64;
        private const int MIN_CHUNK_NUMBER = 0;
        private const int NONCE_LENGTH = 24;
        private const int BASE_NONCE_LENGTH = 16;
        private const int CURRENT_VERSION = 1;
        private const int MIN_VERSION = 1;
        private const int HEADER_CHECKSUM_LENGTH = 64;
        //unused consts
        private const int MAX_FILENAME_LENGTH = 256;
        private const string DEFAULT_FILE_EXTENSION = ".encytepd";

        /// <summary>
        /// Generates an accumulated nonce.
        /// </summary>
        /// <param name="baseNonce">16 byte nonce.</param>
        /// <param name="chunkNumber">Number to accumulate.</param>
        /// <param name="isLastChunkInStream">Idicates if this chunk is the last in the stream.</param>
        /// <returns></returns>
        public static byte[] GetChunkNonce(byte[] baseNonce, int chunkNumber, bool isLastChunkInStream = false)
        {
            //validate the length of the baseNonce
            if (baseNonce == null || baseNonce.Length != BASE_NONCE_LENGTH)
            {
                throw new ArgumentOutOfRangeException("baseNonce", (baseNonce == null) ? 0 : baseNonce.Length,
                  string.Format("baseNonce must be {0} bytes in length.", BASE_NONCE_LENGTH));
            }
            //validate the chunkNumber
            if (chunkNumber < 0)
            {
                throw new ArgumentOutOfRangeException("chunkNumber", string.Format("chunkNumber must be {0} or positive.", MIN_CHUNK_NUMBER));
            }
            //convert the integer to byte[8] array
            byte[] chunkNumberAsByte = Utils.IntegerToLittleEndian(chunkNumber);
            //merge the base nonce with the chunk number
            byte[] concatNonce = ArrayHelpers.ConcatArrays(baseNonce, chunkNumberAsByte);
            //set the last part to 128
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
        /// <param name="maskFileName">Replaces the filename with some random name.</param>
        public static void EncryptFileWithStream(KeyPair keyPair, string inputFile, string outputFile, bool maskFileName = false)
        {
            //validate the keyPair
            if (keyPair == null || keyPair.PrivateKey.Length != 32 || keyPair.PublicKey.Length != 32)
            {
                throw new ArgumentOutOfRangeException("keyPair", "invalid keypair");
            }
            //validate the inputFile
            if (inputFile == null || inputFile.Length < 1)
            {
                throw new ArgumentOutOfRangeException("inputFile", (inputFile == null) ? 0 : inputFile.Length,
                  string.Format("inputFile must be greater {0} in length.", 0));
            }
            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException("inputFile", "inputFile could not be found.");
            }
            //validate the outputFile
            if (outputFile == null || outputFile.Length < 1)
            {
                throw new ArgumentOutOfRangeException("outputFile", (outputFile == null) ? 0 : outputFile.Length,
                  string.Format("outputFile must be greater {0} in length.", 0));
            }
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
                    encryptedFileHeader.Nonce = nonce;
                    //encrypt the ephemeral key with our public box 
                    byte[] encryptedEphemeralKey = Sodium.PublicKeyBox.Create(ephemeralKey, nonce, keyPair.PrivateKey, keyPair.PublicKey);
                    long fileLength = fileStreamUnencrypted.Length;
                    FileInfo inputFileInfo = new FileInfo(inputFile);
                    //we start at chunk number 0
                    int chunkNumber = CHUNK_COUNT_START;
                    //set some things to the file header
                    encryptedFileHeader.UnencryptedFileLength = fileLength;
                    //currently unsued
                    encryptedFileHeader.Version = CURRENT_VERSION;
                    //a random base nonce (16 byte), which will be filled up to 24 byte in every chunk
                    encryptedFileHeader.BaseNonce = SodiumCore.GetRandomBytes(BASE_NONCE_LENGTH);
                    //encryptedEphemeral
                    encryptedFileHeader.Key = encryptedEphemeralKey;
                    //the checksum to validate our file header
                    encryptedFileHeader.Checksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedFileHeader.BaseNonce, Utils.IntegerToLittleEndian(encryptedFileHeader.Version), encryptedFileHeader.Key), ephemeralKey, HEADER_CHECKSUM_LENGTH);
                    //mask the file name
                    if (maskFileName)
                    {
                        //TODO: implement
                        throw new NotImplementedException("bam!");
                        encryptedFileHeader.IsFilenameEncrypted = true;
                        encryptedFileHeader.Filename = Encoding.UTF8.GetBytes(inputFileInfo.Name);
                    }
                    else
                    {
                        encryptedFileHeader.Filename = Encoding.UTF8.GetBytes(inputFileInfo.Name);
                        encryptedFileHeader.IsFilenameEncrypted = false;
                    }
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
                            encryptedFileChunk.ChunkChecksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedChunk, Utils.IntegerToLittleEndian(encryptedChunk.Length), chunkNonce), ephemeralKey, CHUNK_CHECKSUM_LENGTH);
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
            //validate the keyPair
            if (keyPair == null || keyPair.PrivateKey.Length != 32 || keyPair.PublicKey.Length != 32)
            {
                throw new ArgumentOutOfRangeException("keyPair", "invalid keypair");
            }
            //validate the inputFile
            if (inputFile == null || inputFile.Length < 1)
            {
                throw new ArgumentOutOfRangeException("inputFile", (inputFile == null) ? 0 : inputFile.Length,
                  string.Format("inputFile must be greater {0} in length.", 0));
            }
            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException("inputFile", "inputFile could not be found.");
            }
            //validate the outputFile
            if (outputFile == null || outputFile.Length < 1)
            {
                throw new ArgumentOutOfRangeException("outputFile", (outputFile == null) ? 0 : outputFile.Length,
                  string.Format("outputFile must be greater {0} in length.", 0));
            }
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
                    byte[] headerChecksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedFileHeader.BaseNonce, Utils.IntegerToLittleEndian(encryptedFileHeader.Version), encryptedFileHeader.Key), ephemeralKey, HEADER_CHECKSUM_LENGTH);

                    if (encryptedFileHeader.IsFilenameEncrypted)
                    {
                        //TODO: implement
                        throw new NotImplementedException("bam!");
                    }
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
                            byte[] chunkChecksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedFileChunk.Chunk, Utils.IntegerToLittleEndian(encryptedFileChunk.Chunk.Length), chunkNonce), ephemeralKey, CHUNK_CHECKSUM_LENGTH);
                            //check the current chunk checksum
                            if (chunkChecksum.SequenceEqual(encryptedFileChunk.ChunkChecksum))
                            {
                                byte[] decrypted = SecretBox.Open(encryptedFileChunk.Chunk, chunkNonce, ephemeralKey);
                                fileStreamUnencrypted.Write(decrypted, 0, decrypted.Length);
                            }
                            else
                            {
                                throw new BadFileChunkException("Wrong checksum, file could be damaged or manipulated!");
                            }
                            chunkNumber++;
                        }
                    }
                    else
                    {
                        throw new BadFileHeaderException("Malformed file header: file could be damaged or manipulated!");
                    }
                }
            }
        }
    }
}
