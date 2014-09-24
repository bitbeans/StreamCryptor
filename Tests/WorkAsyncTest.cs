using NUnit.Framework;
using Sodium;
using StreamCryptor;
using StreamCryptor.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Tests
{
    /// <summary>
    /// Tests for async encryption and async decryption
    /// </summary>
    [TestFixture]
    public class WorkAsyncTest
    {
        /// <summary>
        /// Self encrypt an image file and decrypt with wrong key async.
        ///</summary>
        [Test]
        [ExpectedException(typeof(CryptographicException))]
        public async void WorkWithImageFileAndWrongKeyTestAsync()
        {
            string RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            string OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            var testKeyPair = Sodium.PublicKeyBox.GenerateKeyPair();
            Console.Write("Encrypting testfile . . .\n");
            //encrypt the file with an ephmeral key
            var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair, testKeyPair.PublicKey, RAW_FILE, null, OUTPUT_DIRECTORY, ".test", true);
            Console.Write("Decrypting testfile . . .\n");
            //try to decrypt with an wrong key
            var decryptedFile = await Cryptor.DecryptFileWithStreamAsync(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), OUTPUT_DIRECTORY);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(RAW_FILE), StreamCryptor.Helper.Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }

        /// <summary>
        /// Self encrypt and decrypt an image file async.
        ///</summary>
        [Test]
        public async void WorkWithImageFileTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n");
            };
            progressDecrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n");
            };
            string RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            string OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey, Utilities.HexToBinary(PUBLIC_KEY), RAW_FILE, progressEncrypt, OUTPUT_DIRECTORY, ".test", true);
            Console.Write("Decrypting testfile . . .\n");
            var decryptedFile = await Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), OUTPUT_DIRECTORY, progressDecrypt);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(RAW_FILE), StreamCryptor.Helper.Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }

        /// <summary>
        /// Encrypt and decrypt an image file async for external.
        ///</summary>
        [Test]
        public async void WorkWithImageFileExternalTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n");
            };
            progressDecrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n");
            };
            string RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            string OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");

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
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(RAW_FILE), StreamCryptor.Helper.Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }
        /// <summary>
        /// Self encrypt and decrypt a very small file async.
        /// </summary>
        [Test]
        public async void WorkWithVerySmallFileTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n");
            };
            progressDecrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n");
            };
            string TESTFILE_RAW = Path.Combine("Testfiles", "verysmallfile.dat");
            string TESTFILE_DECRYPTED_FILE = Path.Combine("Testfiles", "decrypted", "verysmallfile.dat");
            string TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_KB = 1;
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write(string.Format("Generating {0} KB testfile . . .\n", TESTFILE_SIZE_KB));
            FileStream fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_KB * 1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair, TESTFILE_RAW, progressEncrypt, null);
            Console.Write("Decrypting testfile . . .\n");
            await Cryptor.DecryptFileWithStreamAsync(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), TESTFILE_DECRYPTED_OUTPUT_DIRECTORY, progressDecrypt);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_RAW), StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }

        /// <summary>
        /// Self encrypt and decrypt a small file async.
        /// </summary>
        [Test]
        public async void WorkWithSmallFileTesAsynct()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n");
            };
            progressDecrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n");
            };
            string TESTFILE_RAW = Path.Combine("Testfiles", "verysmallfile.dat");
            string TESTFILE_DECRYPTED_FILE = Path.Combine("Testfiles", "decrypted", "verysmallfile.dat");
            string TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_KB = 1024;
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write(string.Format("Generating {0} KB testfile . . .\n", TESTFILE_SIZE_KB));
            FileStream fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_KB * 1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair, TESTFILE_RAW, progressEncrypt, null);
            Console.Write("Decrypting testfile . . .\n");
            await Cryptor.DecryptFileWithStreamAsync(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), TESTFILE_DECRYPTED_OUTPUT_DIRECTORY, progressDecrypt);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_RAW), StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }


        /// <summary>
        /// Self encrypt and decrypt a large file async.
        /// </summary>
        [Test]
        public async void WorkWithLargeFileTestAsync()
        {
            var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
            progressEncrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n");
            };
            progressDecrypt.ProgressChanged += (s, e) =>
            {
                Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n");
            };
            string TESTFILE_RAW = Path.Combine("Testfiles", "largefile.dat");
            string TESTFILE_DECRYPTED_FILE = Path.Combine("Testfiles", "decrypted", "largefile.dat");
            string TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_GB = 1;
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write(string.Format("Generating {0} GB testfile . . .\n", TESTFILE_SIZE_GB));
            System.Diagnostics.Stopwatch testTimer = new System.Diagnostics.Stopwatch();
            //generating
            testTimer.Start();
            FileStream fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_GB * 1024) * 1024 * 1024, SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            testTimer.Stop();
            int elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write(string.Format("Time to generate testfile: {0} s\n", elapsedSeconds));
            testTimer.Reset();
            //encrypting
            testTimer.Start();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey, keyPair.PublicKey, TESTFILE_RAW, progressEncrypt);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write(string.Format("Time to encrypt testfile: {0} s\n", elapsedSeconds));
            testTimer.Reset();
            //decrypting
            testTimer.Start();
            Console.Write("Decrypting testfile . . .\n");
            await Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), TESTFILE_DECRYPTED_OUTPUT_DIRECTORY, progressDecrypt);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write(string.Format("Time to decrypt testfile: {0} s\n", elapsedSeconds));
            testTimer.Reset();
            //checksum
            testTimer.Start();
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_RAW), StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write(string.Format("Time to generate testfile checksums: {0} s\n", elapsedSeconds));
            testTimer.Reset();
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }
    }
}
