using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using NUnit.Framework;
using Sodium;
using StreamCryptor;
using StreamCryptor.Helper;
using StreamCryptor.Model;

namespace Tests
{
    /// <summary>
    ///     Tests for async encryption and async decryption
    /// </summary>
    [TestFixture]
    public class WorkAsyncTest
    {
        /// <summary>
        ///     Encrypt a file from a stream.
        /// </summary>
        [Test]
        public async void WorkWithStreamTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
            progressDecrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
            var RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));

            var data = File.ReadAllBytes(RAW_FILE);
            var stream = new MemoryStream(data);
            Console.Write("Encrypting MemoryStream . . .\n");
            var encryptedFile =
                await
                    Cryptor.EncrypMemoryStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
                        Utilities.HexToBinary(PUBLIC_KEY), "MyAwesomeChipmunkKiller.jpg", stream, OUTPUT_DIRECTORY, ".test", true, progressEncrypt).ConfigureAwait(false);

            Console.Write("Decrypting testfile ("+ encryptedFile + ") . . .\n");
            var decryptedFileObject =
                await
                    Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                        progressDecrypt).ConfigureAwait(false);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(RAW_FILE), Utils.GetChecksum(decryptedFileObject.FileData));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
        }

        /// <summary>
        ///     Encrypt a file from a stream.
        /// </summary>
        [Test]
        public async void WorkWithStreamTestSmallAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
            progressDecrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
         
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));

            var TESTFILE_RAW = Path.Combine("Testfiles", "verysmallfile.dat");
            const long TESTFILE_SIZE_KB = 1;

            Console.Write("Generating {0} KB testfile . . .\n", TESTFILE_SIZE_KB);
            var fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_KB * 1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();

            var data = File.ReadAllBytes(TESTFILE_RAW);
            var stream = new MemoryStream(data);
            Console.Write("Encrypting MemoryStream . . .\n");
            var encryptedFile =
                await
                    Cryptor.EncrypMemoryStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
                        Utilities.HexToBinary(PUBLIC_KEY), TESTFILE_RAW, stream, OUTPUT_DIRECTORY, ".test", true, progressEncrypt).ConfigureAwait(false);

            Console.Write("Decrypting testfile (" + encryptedFile + ") . . .\n");
            var decryptedFileObject =
                await
                    Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                        progressDecrypt).ConfigureAwait(false);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(TESTFILE_RAW), Utils.GetChecksum(decryptedFileObject.FileData));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_RAW);
        }

        /// <summary>
        ///     Self encrypt an image file and decrypt with wrong key async.
        /// </summary>
        [Test]
        [ExpectedException(typeof (CryptographicException))]
        public async void WorkWithImageFileAndWrongKeyTestAsync()
        {
            var RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            var OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            var testKeyPair = PublicKeyBox.GenerateKeyPair();
            Console.Write("Encrypting testfile . . .\n");
            //encrypt the file with an ephmeral key
            var encryptedFile =
                await
                    Cryptor.EncryptFileWithStreamAsync(keyPair, testKeyPair.PublicKey, RAW_FILE, null, OUTPUT_DIRECTORY,
                        ".test", true);
            Console.Write("Decrypting testfile . . .\n");
            //try to decrypt with an wrong key
            var decryptedFile =
                await
                    Cryptor.DecryptFileWithStreamAsync(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                        OUTPUT_DIRECTORY);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(RAW_FILE),
                Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }

        /// <summary>
        ///     Self encrypt and decrypt an image file async.
        /// </summary>
        [Test]
        public async void WorkWithImageFileTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
            progressDecrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
            var RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            var OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile =
                await
                    Cryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
                        Utilities.HexToBinary(PUBLIC_KEY), RAW_FILE, progressEncrypt, OUTPUT_DIRECTORY, ".test", true);
            Console.Write("Decrypting testfile . . .\n");
            var decryptedFile =
                await
                    Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                        OUTPUT_DIRECTORY, progressDecrypt);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(RAW_FILE),
                Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }

        /// <summary>
        ///     Self encrypt and decrypt as byte array an image file async.
        /// </summary>
        [Test]
        public async void WorkWithImageFileByteArrayTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
            progressDecrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
            var RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            var OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile =
                await
                    Cryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
                        Utilities.HexToBinary(PUBLIC_KEY), RAW_FILE, progressEncrypt, OUTPUT_DIRECTORY, ".test", true);
            Console.Write("Decrypting testfile . . .\n");
            var decryptedFileObject =
                await
                    Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                        progressDecrypt);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(RAW_FILE), Utils.GetChecksum(decryptedFileObject.FileData));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
        }

        /// <summary>
        ///     Encrypt and decrypt an image file async for external.
        /// </summary>
        [Test]
        public async void WorkWithImageFileExternalTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
            progressDecrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
            var RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            var OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");

            const string PRIVATE_KEY_RECIPIENT = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY_RECIPIENT = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";

            const string PRIVATE_KEY_SENDER = "da9e790389c2d94d165d60369e0945e3fe50451a55989b80b576ce69f08a24f1";
            const string PUBLIC_KEY_SENDER = "385bb72a7e4ca582b4eb59a364516d885659e753d4b2230c2f03f2e495b21c42";

            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(
                Utilities.HexToBinary(PRIVATE_KEY_SENDER),
                Utilities.HexToBinary(PUBLIC_KEY_SENDER),
                Utilities.HexToBinary(PUBLIC_KEY_RECIPIENT),
                RAW_FILE, progressEncrypt, OUTPUT_DIRECTORY, ".whatever", true);

            Console.Write("Decrypting testfile (" + encryptedFile + ") . . .\n");
            var decryptedFile = await Cryptor.DecryptFileWithStreamAsync(
                Utilities.HexToBinary(PRIVATE_KEY_RECIPIENT),
                Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                OUTPUT_DIRECTORY, progressDecrypt);

            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(RAW_FILE),
                Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }

        /// <summary>
        ///     Self encrypt and decrypt a very small file async.
        /// </summary>
        [Test]
        public async void WorkWithVerySmallFileTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
            progressDecrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
            var TESTFILE_RAW = Path.Combine("Testfiles", "verysmallfile.dat");
            var TESTFILE_DECRYPTED_FILE = Path.Combine("Testfiles", "decrypted", "verysmallfile.dat");
            var TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_KB = 1;
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write("Generating {0} KB testfile . . .\n", TESTFILE_SIZE_KB);
            var fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_KB*1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair, TESTFILE_RAW, progressEncrypt);
            Console.Write("Decrypting testfile . . .\n");
            await
                Cryptor.DecryptFileWithStreamAsync(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                    TESTFILE_DECRYPTED_OUTPUT_DIRECTORY, progressDecrypt);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(TESTFILE_RAW), Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }

        /// <summary>
        ///     Self encrypt and decrypt a small file async.
        /// </summary>
        [Test]
        public async void WorkWithSmallFileTesAsynct()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
            progressDecrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
            var TESTFILE_RAW = Path.Combine("Testfiles", "verysmallfile.dat");
            var TESTFILE_DECRYPTED_FILE = Path.Combine("Testfiles", "decrypted", "verysmallfile.dat");
            var TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_KB = 1024;
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write("Generating {0} KB testfile . . .\n", TESTFILE_SIZE_KB);
            var fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_KB*1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair, TESTFILE_RAW, progressEncrypt);
            Console.Write("Decrypting testfile . . .\n");
            await
                Cryptor.DecryptFileWithStreamAsync(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                    TESTFILE_DECRYPTED_OUTPUT_DIRECTORY, progressDecrypt);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(TESTFILE_RAW), Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }

        /// <summary>
        ///     Self encrypt and decrypt a large file async.
        /// </summary>
        [Test]
        public async void WorkWithLargeFileTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
            progressDecrypt.ProgressChanged +=
                (s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
            var TESTFILE_RAW = Path.Combine("Testfiles", "largefile.dat");
            var TESTFILE_DECRYPTED_FILE = Path.Combine("Testfiles", "decrypted", "largefile.dat");
            var TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_GB = 1;
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write("Generating {0} GB testfile . . .\n", TESTFILE_SIZE_GB);
            var testTimer = new Stopwatch();
            //generating
            testTimer.Start();
            var fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_GB*1024)*1024*1024, SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            testTimer.Stop();
            var elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write("Time to generate testfile: {0} s\n", elapsedSeconds);
            testTimer.Reset();
            //encrypting
            testTimer.Start();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile =
                await
                    Cryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey, keyPair.PublicKey,
                        TESTFILE_RAW, progressEncrypt);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write("Time to encrypt testfile: {0} s\n", elapsedSeconds);
            testTimer.Reset();
            //decrypting
            testTimer.Start();
            Console.Write("Decrypting testfile . . .\n");
            await
                Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                    TESTFILE_DECRYPTED_OUTPUT_DIRECTORY, progressDecrypt);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write("Time to decrypt testfile: {0} s\n", elapsedSeconds);
            testTimer.Reset();
            //checksum
            testTimer.Start();
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(TESTFILE_RAW), Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write("Time to generate testfile checksums: {0} s\n", elapsedSeconds);
            testTimer.Reset();
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }
    }
}