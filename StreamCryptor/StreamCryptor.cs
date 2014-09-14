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
        private const int CHUNK_LENGTH = 1048576; //~1MB
        private const int CHUNK_COUNT_START = 0;
        private const int CHUNK_CHECKSUM_LENGTH = 64;
        private const int MIN_CHUNK_NUMBER = 0;
        private const int NONCE_LENGTH = 24;
        private const int BASE_NONCE_LENGTH = 16;
        private const int CURRENT_VERSION = 1;
        private const int MIN_VERSION = 1;
        private const int HEADER_CHECKSUM_LENGTH = 64;
        private const int MAX_FILENAME_LENGTH = 256;
        private const int MASKED_FILENAME_LENGTH = 11;
        private const string DEFAULT_FILE_EXTENSION = ".encrypted";
        private const string TEMP_FILE_EXTENSION = ".t";

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
        /// <param name="inputFile">The input file.</param>
        /// <param name="maskFileName">Replaces the filename with some random name.</param>
        /// <returns>The name of the encrypted file.</returns>
        /// <remarks>The outputFolder is equal to the inputFolder.</remarks>
        public static string EncryptFileWithStream(KeyPair keyPair, string inputFile, bool maskFileName = false)
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
            //retrieve file info
            FileInfo inputFileInfo = new FileInfo(inputFile);
            string outputFile = String.Empty;
            if (inputFileInfo.Name.Length > MAX_FILENAME_LENGTH)
            {
                throw new ArgumentOutOfRangeException("inputFile", string.Format("inputFile name must be smaller {0} in length.", MAX_FILENAME_LENGTH));
            }
            //Call the main method
            return EncryptFileWithStream(keyPair, inputFile, inputFileInfo.DirectoryName, maskFileName);
        }

        /// <summary>
        /// Encrypts a file with libsodium and protobuf-net.
        /// </summary>
        /// <param name="keyPair">A KeyPair to encrypt the ephemeralKey.</param>
        /// <param name="inputFile">The input file.</param>
        /// <param name="outputFolder">There the encrypted file will be stored.</param>
        /// <param name="maskFileName">Replaces the filename with some random name.</param>
        /// <returns>The name of the encrypted file.</returns>
        public static string EncryptFileWithStream(KeyPair keyPair, string inputFile, string outputFolder, bool maskFileName = false)
        {
            string outputFullPath = String.Empty;
            string outputFile = String.Empty;
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
            //retrieve file info
            FileInfo inputFileInfo = new FileInfo(inputFile);
            if (inputFileInfo.Name.Length > MAX_FILENAME_LENGTH)
            {
                throw new ArgumentOutOfRangeException("inputFile", string.Format("inputFile name must be smaller {0} in length.", MAX_FILENAME_LENGTH));
            }
            //validate the outputFolder
            if (outputFolder == null || !Directory.Exists(outputFolder))
            {
                throw new DirectoryNotFoundException("outputFolder must exist");
            }
            //generate the name of the output file
            if (maskFileName)
            {
                //store the output file with a masked file name and the DEFAULT_FILE_EXTENSION
                outputFile = Helper.Utils.GetRandomString(MASKED_FILENAME_LENGTH) + DEFAULT_FILE_EXTENSION;
                outputFullPath = Path.Combine(outputFolder, outputFile);
            }
            else
            {
                //store the output file, just with the DEFAULT_FILE_EXTENSION
                outputFile = inputFileInfo.Name + DEFAULT_FILE_EXTENSION;
                outputFullPath = Path.Combine(outputFolder, outputFile);
            }
            //prepare our file header
            EncryptedFileHeader encryptedFileHeader = new EncryptedFileHeader();
            //go for the streams
            using (FileStream fileStreamEncrypted = File.OpenWrite(outputFullPath))
            {
                using (FileStream fileStreamUnencrypted = File.OpenRead(inputFile))
                {
                    //get some ephemeral key fot this file
                    byte[] ephemeralKey = SecretBox.GenerateKey();
                    //generate a nonce for the encrypted ephemeral key
                    byte[] ephemeralNonce = Sodium.SodiumCore.GetRandomBytes(NONCE_LENGTH);
                    encryptedFileHeader.EphemeralNonce = ephemeralNonce;
                    //encrypt the ephemeral key with our public box 
                    byte[] encryptedEphemeralKey = Sodium.PublicKeyBox.Create(ephemeralKey, ephemeralNonce, keyPair.PrivateKey, keyPair.PublicKey);
                    long fileLength = fileStreamUnencrypted.Length;
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
                    encryptedFileHeader.Checksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedFileHeader.BaseNonce, Utils.IntegerToLittleEndian(encryptedFileHeader.Version), encryptedFileHeader.Key, BitConverter.GetBytes(fileLength)), ephemeralKey, HEADER_CHECKSUM_LENGTH);
                    //encrypt the file name in the header
                    byte[] fileNameNonce = Sodium.SodiumCore.GetRandomBytes(NONCE_LENGTH);
                    encryptedFileHeader.FilenameNonce = fileNameNonce;
                    //get the filename to 256 bytes
                    byte[] paddedFileName = Helper.Utils.StringToPaddedByteArray(inputFileInfo.Name, MAX_FILENAME_LENGTH);
                    encryptedFileHeader.Filename = SecretBox.Create(paddedFileName, fileNameNonce, ephemeralKey);
                    //write the file header
                    Serializer.SerializeWithLengthPrefix(fileStreamEncrypted, encryptedFileHeader, PrefixStyle.Fixed32);
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
                            Serializer.SerializeWithLengthPrefix(fileStreamEncrypted, encryptedFileChunk, PrefixStyle.Fixed32);
                            //increment for the next chunk
                            chunkNumber++;
                        }
                    } while (bytesRead != 0);
                    
                }
                
            }
            return outputFile;
        }

        /// <summary>
        /// Decrypts a file with libsodium and protobuf-net.
        /// </summary>
        /// <param name="keyPair">A KeyPair to decrypt the ephemeralKey.</param>
        /// <param name="inputFile">An encrypted file.</param>
        /// <param name="outputFolder">There the decrypted file will be stored.</param>
        /// <param name="overWrite">Overwrite the output file if it exist.</param>
        /// <returns>The fullpath to the decrypted file.</returns>
        public static string DecryptFileWithStream(KeyPair keyPair, string inputFile, string outputFolder, bool overWrite = false)
        {
            string outputFile = String.Empty;
            string outputFullPath = String.Empty;
            //used to check the file length of the unencrypted file, will be renamed to the outputFile (if the file is valid)
            string tmpFile = String.Empty;
            string tmpFullPath = String.Empty;
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
            //validate the outputFolder
            if (outputFolder == null || !Directory.Exists(outputFolder))
            {
                throw new DirectoryNotFoundException("outputFolder must exist");
            }

            //get a tmp name
            tmpFile = Utils.GetRandomString(MASKED_FILENAME_LENGTH) + TEMP_FILE_EXTENSION;
            tmpFullPath = Path.Combine(outputFolder, tmpFile);
            
            
            using (FileStream fileStreamEncrypted = File.OpenRead(inputFile))
            {
                //first read the file header
                EncryptedFileHeader encryptedFileHeader = new EncryptedFileHeader();
                encryptedFileHeader = Serializer.DeserializeWithLengthPrefix<EncryptedFileHeader>(fileStreamEncrypted, PrefixStyle.Fixed32);
                //decrypt the ephemeral key with our public box 
                byte[] ephemeralKey = Sodium.PublicKeyBox.Open(encryptedFileHeader.Key, encryptedFileHeader.EphemeralNonce, keyPair.PublicKey, keyPair.PrivateKey);
                byte[] headerChecksum = Sodium.GenericHash.Hash(ArrayHelpers.ConcatArrays(encryptedFileHeader.BaseNonce, Utils.IntegerToLittleEndian(encryptedFileHeader.Version), encryptedFileHeader.Key, BitConverter.GetBytes(encryptedFileHeader.UnencryptedFileLength)), ephemeralKey, HEADER_CHECKSUM_LENGTH);
                //check file header
                if ((encryptedFileHeader.Version >= MIN_VERSION) &&
                    (encryptedFileHeader.BaseNonce.Length == BASE_NONCE_LENGTH) &&
                    (encryptedFileHeader.Checksum.SequenceEqual(headerChecksum)))
                {
                    //restore the original file name
                    byte[] encryptedPaddedFileName = encryptedFileHeader.Filename = SecretBox.Open(encryptedFileHeader.Filename, encryptedFileHeader.FilenameNonce, ephemeralKey); ;
                    //remove the padding
                    outputFile = Helper.Utils.PaddedByteArrayToString(encryptedPaddedFileName);
                    outputFullPath = Path.Combine(outputFolder, outputFile);
                    //write the file to the tmpFullPath
                    using (FileStream fileStreamUnencrypted = File.OpenWrite(tmpFullPath))
                    {
                        int chunkNumber = CHUNK_COUNT_START;
                        //start reading the chunks
                        EncryptedFileChunk encryptedFileChunk = new EncryptedFileChunk();
                        while ((encryptedFileChunk = Serializer.DeserializeWithLengthPrefix<EncryptedFileChunk>(fileStreamEncrypted, PrefixStyle.Fixed32)) != null)
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
                }
                else
                {
                    throw new BadFileHeaderException("Malformed file header: file could be damaged or manipulated!");
                }
                //check the produced output for the correct length
                //NOTICE: we also could use a file checksum, but this would lower the speed
                if (encryptedFileHeader.UnencryptedFileLength == new FileInfo(tmpFullPath).Length)
                {
                    //check if the new output file already exists
                    if (File.Exists(outputFullPath)) {
                        if (!overWrite)
                        {
                            //we don`t overwrite the file
                            throw new IOException("Decrypted file aleary exits, won`t overwrite");
                        }
                        else
                        {
                            //just delete the output file, so we can write a new one
                            File.Delete(outputFullPath);
                        }
                    }
                    File.Move(tmpFullPath, outputFullPath);
                }
                else
                {
                    //File is not valid (return null)
                    outputFile = null;
                    File.Delete(tmpFullPath);
                }
            }
            
            return outputFile;
        }
    }
}
