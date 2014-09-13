using NUnit.Framework;
using Sodium;
using System;
using System.IO;

namespace Tests
{
    [TestFixture]
    public class StreamCryptorTests
    {
        /// <summary>
        /// EncryptFileWithStream and DecryptFileWithStream
        ///</summary>
        [Test]
        public void StreamCryptorUsualTest()
        {
            const string RAW_FILE = "Testfiles\\MyAwesomeChipmunkKiller.jpg";
            const string ENCRYPTED_FILE = "Testfiles\\MyAwesomeChipmunkKiller.jpg.encrypted";
            const string DECRYPTED_FILE = "Testfiles\\decrypted\\MyAwesomeChipmunkKiller.jpg";
            const string DECRYPTED_OUTPUT_DIRECTORY = "Testfiles\\decrypted";
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));

            StreamCryptor.StreamCryptor.EncryptFileWithStream(keyPair, RAW_FILE, false);
            StreamCryptor.StreamCryptor.DecryptFileWithStream(keyPair, ENCRYPTED_FILE, DECRYPTED_OUTPUT_DIRECTORY);

            //get a SHA256 checksum to validate our work, this takes us currently ~100ms on a SSD and this testfile.
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(RAW_FILE), StreamCryptor.Helper.Utils.GetChecksum(DECRYPTED_FILE));
 
            //clear garbage 
            File.Delete(ENCRYPTED_FILE);
            File.Delete(DECRYPTED_FILE);
        }

        /// <summary>
        /// EncryptFileWithStream and DecryptFileWithStream a random generated file
        /// </summary>
        [Test]
        public void StreamCryptorBigFileTest()
        {
            const string TESTFILE_RAW = "Testfiles\\bigfile.dat";
            const string TESTFILE_ENCRYPTED = "Testfiles\\bigfile.dat.encrypted";
            const string TESTFILE_DECRYPTED_FILE = "Testfiles\\decrypted\\bigfile.dat";
            const string TESTFILE_DECRYPTED_OUTPUT_DIRECTORY = "Testfiles\\decrypted";
            const long TESTFILE_SIZE_GB = 1;
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write(string.Format("Generating {0} GB testfile . . .", TESTFILE_SIZE_GB));
            System.Diagnostics.Stopwatch testTimer = new System.Diagnostics.Stopwatch();
            //generating
            testTimer.Start();
            FileStream fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
            fs.Seek((TESTFILE_SIZE_GB * 1024) * 1024 * 1024, SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            testTimer.Stop();
            int elapsedSeconds = testTimer.Elapsed.Milliseconds;
            Console.Write(string.Format("Time to generate testfile: {0} ms", elapsedSeconds));
            testTimer.Reset();
            //encrypting
            testTimer.Start();
            Console.Write("Encrypting testfile . . .");
            StreamCryptor.StreamCryptor.EncryptFileWithStream(keyPair, TESTFILE_RAW, false);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Milliseconds;
            Console.Write(string.Format("Time to encrypt testfile: {0} ms", elapsedSeconds));
            testTimer.Reset();
            //decrypting
            testTimer.Start();
            Console.Write("Decrypting testfile . . .");
            StreamCryptor.StreamCryptor.DecryptFileWithStream(keyPair, TESTFILE_ENCRYPTED, TESTFILE_DECRYPTED_OUTPUT_DIRECTORY);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Milliseconds;
            Console.Write(string.Format("Time to decrypt testfile: {0} ms", elapsedSeconds));
            testTimer.Reset();
            //checksum
            testTimer.Start();
            Console.Write("Get checksum of testfiles . . .");
            Assert.AreEqual(StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_RAW), StreamCryptor.Helper.Utils.GetChecksum(TESTFILE_DECRYPTED_FILE));
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Milliseconds;
            Console.Write(string.Format("Time to generate testfile checksums: {0} ms", elapsedSeconds));
            testTimer.Reset();
            //clear garbage 
            File.Delete(TESTFILE_RAW);
            File.Delete(TESTFILE_ENCRYPTED);
            File.Delete(TESTFILE_DECRYPTED_FILE);
        }
    }
}
