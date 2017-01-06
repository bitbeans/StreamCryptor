using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using NUnit.Framework;
using Sodium;
using StreamCryptor;
using StreamCryptor.Helper;

namespace Tests
{
    /// <summary>
    ///     Tests for encryption and decryption
    /// </summary>
    [TestFixture]
    public class WorkTests
    {
	    /// <summary>
	    ///     Self encrypt an image file and decrypt with wrong key.
	    /// </summary>
	    [Test]
	    public void WorkWithImageFileAndWrongKeyTest()
	    {
		    var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
		    var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
		    const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
		    const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
		    var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
		    var testKeyPair = PublicKeyBox.GenerateKeyPair();
		    Console.Write("Encrypting testfile . . .\n");
		    //encrypt the file with an ephmeral key
		    var encryptedFile = Cryptor.EncryptFileWithStream(keyPair, testKeyPair.PublicKey, rawFile, outputDirectory,
			    ".test", true);
		    Console.Write("Decrypting testfile . . .\n");
			//try to decrypt with an wrong key
			Assert.Throws<CryptographicException>(
				() =>
				{
					Cryptor.DecryptFileWithStream(keyPair, Path.Combine(outputDirectory, encryptedFile),
				outputDirectory);
				});

		    //clear garbage 
		    File.Delete(Path.Combine(outputDirectory, encryptedFile));
		}

	    /// <summary>
        ///     Self encrypt and decrypt an image file.
        /// </summary>
        [Test]
        public void WorkWithImageFileTest()
        {
            var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
            var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
            const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = Cryptor.EncryptFileWithStream(keyPair, Utilities.HexToBinary(publicKey), rawFile,
                outputDirectory, ".test", true);
            Console.Write("Decrypting testfile . . .\n");
            var decryptedFile = Cryptor.DecryptFileWithStream(keyPair, Path.Combine(outputDirectory, encryptedFile),
                outputDirectory);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(rawFile),
                Utils.GetChecksum(Path.Combine(outputDirectory, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(outputDirectory, encryptedFile));
            File.Delete(Path.Combine(outputDirectory, decryptedFile));
        }

        /// <summary>
        ///     Encrypt and decrypt an image file for external.
        /// </summary>
        [Test]
        public void WorkWithImageFileExternalTest()
        {
            var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
            var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
            const string privateKeyRecipient = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string publicKeyRecipient = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            const string privateKeySender = "da9e790389c2d94d165d60369e0945e3fe50451a55989b80b576ce69f08a24f1";
            const string publicKeySender = "385bb72a7e4ca582b4eb59a364516d885659e753d4b2230c2f03f2e495b21c42";
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = Cryptor.EncryptFileWithStream(
                Utilities.HexToBinary(privateKeySender),
                Utilities.HexToBinary(publicKeySender),
                Utilities.HexToBinary(publicKeyRecipient),
                rawFile, outputDirectory, ".whatever", true);

            Console.Write("Decrypting testfile (" + encryptedFile + ") . . .\n");
            var decryptedFile = Cryptor.DecryptFileWithStream(
                Utilities.HexToBinary(privateKeyRecipient),
                Path.Combine(outputDirectory, encryptedFile),
                outputDirectory);

            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(rawFile),
                Utils.GetChecksum(Path.Combine(outputDirectory, decryptedFile)));
            //clear garbage 
            File.Delete(Path.Combine(outputDirectory, encryptedFile));
            File.Delete(Path.Combine(outputDirectory, decryptedFile));
        }



		/// <summary>
		///     Self encrypt and decrypt a very small file.
		/// </summary>
		[Test]
        public void WorkWithVerySmallFileTest()
        {
            var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "verysmallfile.dat");
            var testfileDecryptedFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted", "verysmallfile.dat");
            var testfileDecryptedOutputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
            const string outputDirectory = "Testfiles";
            const long testfileSizeKb = 1;
            const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
            Console.Write("Generating {0} KB testfile . . .\n", testfileSizeKb);
            var fs = new FileStream(testfileRaw, FileMode.CreateNew);
            fs.Seek((testfileSizeKb*1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = Cryptor.EncryptFileWithStream(keyPair, testfileRaw);
            Console.Write("Decrypting testfile . . .\n");
            Cryptor.DecryptFileWithStream(keyPair, Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
                testfileDecryptedOutputDirectory);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(testfileRaw), Utils.GetChecksum(testfileDecryptedFile));
            //clear garbage 
            File.Delete(testfileRaw);
            File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
            File.Delete(testfileDecryptedFile);
        }

        /// <summary>
        ///     Self encrypt and decrypt a small file.
        /// </summary>
        [Test]
        public void WorkWithSmallFileTest()
        {
            var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "verysmallfile.dat");
            var testfileDecryptedFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted", "verysmallfile.dat");
            var testfileDecryptedOutputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
            const string outputDirectory = "Testfiles";
            const long testfileSizeKb = 1024;
            const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
            Console.Write("Generating {0} KB testfile . . .\n", testfileSizeKb);
            var fs = new FileStream(testfileRaw, FileMode.CreateNew);
            fs.Seek((testfileSizeKb*1024), SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = Cryptor.EncryptFileWithStream(keyPair, testfileRaw);
            Console.Write("Decrypting testfile . . .\n");
            Cryptor.DecryptFileWithStream(keyPair, Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
                testfileDecryptedOutputDirectory);
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(testfileRaw), Utils.GetChecksum(testfileDecryptedFile));
            //clear garbage 
            File.Delete(testfileRaw);
            File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
            File.Delete(testfileDecryptedFile);
        }


		/// <summary>
		///     Self encrypt and decrypt a large file.
		/// </summary>
		[Test]
        public void WorkWithLargeFileTest()
        {
            var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "largefile.dat");
            var testfileDecryptedFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted", "largefile.dat");
            var testfileDecryptedOutputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
            const string outputDirectory = "Testfiles";
            const long testfileSizeGb = 1;
            const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
            Console.Write("Generating {0} GB testfile . . .\n", testfileSizeGb);
            var testTimer = new Stopwatch();
            //generating
            testTimer.Start();
            var fs = new FileStream(testfileRaw, FileMode.CreateNew);
            fs.Seek((testfileSizeGb*1024)*1024*1024, SeekOrigin.Begin);
            fs.WriteByte(0);
            fs.Close();
            testTimer.Stop();
            var elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write("Time to generate testfile: {0} s\n", elapsedSeconds);
            testTimer.Reset();
            //encrypting
            testTimer.Start();
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile = Cryptor.EncryptFileWithStream(keyPair, testfileRaw);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write("Time to encrypt testfile: {0} s\n", elapsedSeconds);
            testTimer.Reset();
            //decrypting
            testTimer.Start();
            Console.Write("Decrypting testfile . . .\n");
            Cryptor.DecryptFileWithStream(keyPair, Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
                testfileDecryptedOutputDirectory);
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write("Time to decrypt testfile: {0} s\n", elapsedSeconds);
            testTimer.Reset();
            //checksum
            testTimer.Start();
            Console.Write("Get checksum of testfiles . . .\n");
            Assert.AreEqual(Utils.GetChecksum(testfileRaw), Utils.GetChecksum(testfileDecryptedFile));
            testTimer.Stop();
            elapsedSeconds = testTimer.Elapsed.Seconds;
            Console.Write("Time to generate testfile checksums: {0} s\n", elapsedSeconds);
            testTimer.Reset();
            //clear garbage 
            File.Delete(testfileRaw);
            File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
            File.Delete(testfileDecryptedFile);
        }
    }
}