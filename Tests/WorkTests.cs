using NUnit.Framework;
using Sodium;
using StreamCryptor.Model;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Tests
{
    /// <summary>
    /// Tests for encryption and decryption
    /// </summary>
    [TestFixture]
    public class WorkTests
    {
        /// <summary>
        /// Self encrypt an image file and decrypt with wrong key.
        ///</summary>
        [Test]
        [ExpectedException(typeof(CryptographicException))]
        public void WorkWithImageFileAndWrongKeyTest()
        {
            const string RAW_FILE = "Testfiles\\MyAwesomeChipmunkKiller.jpg";
            const string OUTPUT_DIRECTORY = "Testfiles\\decrypted";
            string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            KeyPair keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            KeyPair testKeyPair = Sodium.PublicKeyBox.GenerateKeyPair();
            Console.Write("Encrypting testfile . . .\n");
            //encrypt the file with an ephmeral key
            string encryptedFile = StreamCryptor.StreamCryptor.EncryptFileWithStream(keyPair, testKeyPair.PublicKey, RAW_FILE, OUTPUT_DIRECTORY, ".test", true);
            Console.Write("Decrypting testfile . . .\n");
            //try to decrypt with an wrong key
            string decryptedFile = StreamCryptor.StreamCryptor.DecryptFileWithStream(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), OUTPUT_DIRECTORY);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(RAW_FILE), StreamCryptor.Helper.Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }

        /// <summary>
        /// Self encrypt and decrypt an image file.
        ///</summary>
        [Test]
        public void WorkWithImageFileTest()
        {
            const string RAW_FILE = "Testfiles\\MyAwesomeChipmunkKiller.jpg";
            const string OUTPUT_DIRECTORY = "Testfiles\\decrypted";
            string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            KeyPair keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write("Encrypting testfile . . .\n");
            string encryptedFile = StreamCryptor.StreamCryptor.EncryptFileWithStream(keyPair, Utilities.HexToBinary(PUBLIC_KEY), RAW_FILE, OUTPUT_DIRECTORY, ".test", true);
            Console.Write("Decrypting testfile . . .\n");
            string decryptedFile = StreamCryptor.StreamCryptor.DecryptFileWithStream(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), OUTPUT_DIRECTORY);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(RAW_FILE), StreamCryptor.Helper.Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }

        /// <summary>
        /// Encrypt and decrypt an image file for external.
        ///</summary>
        [Test]
        public void WorkWithImageFileExternalTest()
        {
            const string RAW_FILE = "Testfiles\\MyAwesomeChipmunkKiller.jpg";
            const string OUTPUT_DIRECTORY = "Testfiles\\decrypted";

            string PRIVATE_KEY_RECIPIENT = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            string PUBLIC_KEY_RECIPIENT = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";

            string PRIVATE_KEY_SENDER = "da9e790389c2d94d165d60369e0945e3fe50451a55989b80b576ce69f08a24f1";
            string PUBLIC_KEY_SENDER = "385bb72a7e4ca582b4eb59a364516d885659e753d4b2230c2f03f2e495b21c42";

            Console.Write("Encrypting testfile . . .\n");
            string encryptedFile = StreamCryptor.StreamCryptor.EncryptFileWithStream(
                Utilities.HexToBinary(PRIVATE_KEY_SENDER),
                Utilities.HexToBinary(PUBLIC_KEY_SENDER), 
                Utilities.HexToBinary(PUBLIC_KEY_RECIPIENT), 
                RAW_FILE, OUTPUT_DIRECTORY, ".whatever", true);

            Console.Write("Decrypting testfile (" + encryptedFile + ") . . .\n");
            string decryptedFile = StreamCryptor.StreamCryptor.DecryptFileWithStream(
                Utilities.HexToBinary(PRIVATE_KEY_RECIPIENT), 
                Path.Combine(OUTPUT_DIRECTORY, encryptedFile), 
                OUTPUT_DIRECTORY);

            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(RAW_FILE), StreamCryptor.Helper.Utils.GetChecksum(Path.Combine(OUTPUT_DIRECTORY, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, decryptedFile));
        }

        /// <summary>
        /// Self encrypt and decrypt a very small file.
        /// </summary>
        [Test]
        public void WorkWithVerySmallFileTest()
        {
            const string TESTFILE_RAW = "Testfiles\\verysmallfile.dat";
            const string TESTFILE_DECRYPTED_FILE = "Testfiles\\decrypted\\verysmallfile.dat";
            const string TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = "Testfiles\\decrypted";
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_KB = 1;
            string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            KeyPair keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write(string.Format("Generating {0} KB testfile . . .\n", TESTFILE_SIZE_KB));
            FileStream fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_KB * 1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            Console.Write("Encrypting testfile . . .\n");
            string encryptedFile = StreamCryptor.StreamCryptor.EncryptFileWithStream(keyPair, TESTFILE_RAW, null);
            Console.Write("Decrypting testfile . . .\n");
            StreamCryptor.StreamCryptor.DecryptFileWithStream(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), TESTFILE_DECRYPTED_OUTPUT_DIRECTORY);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_RAW), StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }

        /// <summary>
        /// Self encrypt and decrypt a small file.
        /// </summary>
        [Test]
        public void WorkWithSmallFileTest()
        {
            const string TESTFILE_RAW = "Testfiles\\verysmallfile.dat";
            const string TESTFILE_DECRYPTED_FILE = "Testfiles\\decrypted\\verysmallfile.dat";
            const string TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = "Testfiles\\decrypted";
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_KB = 1024;
            string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            KeyPair keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write(string.Format("Generating {0} KB testfile . . .\n", TESTFILE_SIZE_KB));
            FileStream fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_KB * 1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            Console.Write("Encrypting testfile . . .\n");
            string encryptedFile = StreamCryptor.StreamCryptor.EncryptFileWithStream(keyPair, TESTFILE_RAW, null);
            Console.Write("Decrypting testfile . . .\n");
            StreamCryptor.StreamCryptor.DecryptFileWithStream(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), TESTFILE_DECRYPTED_OUTPUT_DIRECTORY);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_RAW), StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(Path.Combine(OUTPUT_DIRECTORY, encryptedFile));
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }

        /// <summary>
        /// Self encrypt and decrypt a large file.
        /// </summary>
        [Test]
        public void WorkWithLargeFileTest()
        {
            const string TESTFILE_RAW = "Testfiles\\largefile.dat";
            const string TESTFILE_DECRYPTED_FILE = "Testfiles\\decrypted\\largefile.dat";
            const string TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = "Testfiles\\decrypted";
            const string OUTPUT_DIRECTORY = "Testfiles";
            const long TESTFILE_SIZE_GB = 1;
            string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            KeyPair keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
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
            string encryptedFile = StreamCryptor.StreamCryptor.EncryptFileWithStream(keyPair, TESTFILE_RAW, null);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write(string.Format("Time to encrypt testfile: {0} s\n", elapsedSeconds));
            testTimer.Reset();
            //decrypting
            testTimer.Start();
            Console.Write("Decrypting testfile . . .\n");
            StreamCryptor.StreamCryptor.DecryptFileWithStream(keyPair, Path.Combine(OUTPUT_DIRECTORY, encryptedFile), TESTFILE_DECRYPTED_OUTPUT_DIRECTORY);
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
