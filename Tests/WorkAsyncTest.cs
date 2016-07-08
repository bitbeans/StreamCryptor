using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
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
		///     Self encrypt an image file and decrypt with wrong key async.
		/// </summary>
		[Test]
		public async Task WorkWithImageFileAndWrongKeyTestAsync()
		{
			var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
			const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
			var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			var testKeyPair = PublicKeyBox.GenerateKeyPair();
			Console.Write("Encrypting testfile . . .\n");
			//encrypt the file with an ephmeral key
			var encryptedFile =
				await
					Cryptor.EncryptFileWithStreamAsync(keyPair, testKeyPair.PublicKey, rawFile, null, outputDirectory,
						".test", true);
			Console.Write("Decrypting testfile . . .\n");
			//try to decrypt with an wrong key
			var decryptedFile =
				Assert.ThrowsAsync<CryptographicException>(
					async () => await
						Cryptor.DecryptFileWithStreamAsync(keyPair,
							Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
							outputDirectory));


			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
		}

		/// <summary>
		///     Self encrypt and decrypt as byte array an image file async.
		/// </summary>
		[Test]
		public async Task WorkWithImageFileByteArrayTestAsync()
		{
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
			var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
			const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
			var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Console.Write("Encrypting testfile . . .\n");
			var encryptedFile =
				await
					Cryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
						Utilities.HexToBinary(publicKey), rawFile, progressEncrypt, outputDirectory, ".test", true);
			Console.Write("Decrypting testfile . . .\n");
			var decryptedFileObject =
				await
					Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey,
						Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
						progressDecrypt);
			Console.Write("Get checksum of testfiles . . .\n");
			Assert.AreEqual(Utils.GetChecksum(rawFile), Utils.GetChecksum(decryptedFileObject.FileData));
			//clear garbage 
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
		}

		/// <summary>
		///     Encrypt and decrypt an image file async for external.
		/// </summary>
		[Test]
		public async Task WorkWithImageFileExternalTestAsync()
		{
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
			var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");

			const string privateKeyRecipient = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKeyRecipient = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";

			const string privateKeySender = "da9e790389c2d94d165d60369e0945e3fe50451a55989b80b576ce69f08a24f1";
			const string publicKeySender = "385bb72a7e4ca582b4eb59a364516d885659e753d4b2230c2f03f2e495b21c42";

			Console.Write("Encrypting testfile . . .\n");
			var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(
				Utilities.HexToBinary(privateKeySender),
				Utilities.HexToBinary(publicKeySender),
				Utilities.HexToBinary(publicKeyRecipient),
				rawFile, progressEncrypt, outputDirectory, ".whatever", true);

			Console.Write("Decrypting testfile (" + encryptedFile + ") . . .\n");
			var decryptedFile = await Cryptor.DecryptFileWithStreamAsync(
				Utilities.HexToBinary(privateKeyRecipient),
				Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
				outputDirectory, progressDecrypt);

			Console.Write("Get checksum of testfiles . . .\n");
			Assert.AreEqual(Utils.GetChecksum(rawFile),
				Utils.GetChecksum(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, decryptedFile)));
			//clear garbage 
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, decryptedFile));
		}

		/// <summary>
		///     Self encrypt and decrypt an image file async.
		/// </summary>
		[Test]
		public async Task WorkWithImageFileTestAsync()
		{
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
			var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
			const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
			var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Console.Write("Encrypting testfile . . .\n");
			var encryptedFile =
				await
					Cryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
						Utilities.HexToBinary(publicKey), rawFile, progressEncrypt, outputDirectory, ".test", true);
			Console.Write("Decrypting testfile . . .\n");
			var decryptedFile =
				await
					Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey,
						Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
						outputDirectory, progressDecrypt);
			Console.Write("Get checksum of testfiles . . .\n");
			Assert.AreEqual(Utils.GetChecksum(rawFile),
				Utils.GetChecksum(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, decryptedFile)));
			//clear garbage 
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, decryptedFile));
		}

		/// <summary>
		///     Self encrypt and decrypt a large file async.
		/// </summary>
		[Test]
		public async Task WorkWithLargeFileTestAsync()
		{
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "largefile.dat");
			var testfileDecryptedFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted",
				"largefile.dat");
			var testfileDecryptedOutputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles",
				"decrypted");
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
			fs.Seek(testfileSizeGb*1024*1024*1024, SeekOrigin.Begin);
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
						testfileRaw, progressEncrypt);
			testTimer.Stop();
			elapsedSeconds = testTimer.Elapsed.Seconds;
			Console.Write("Time to encrypt testfile: {0} s\n", elapsedSeconds);
			testTimer.Reset();
			//decrypting
			testTimer.Start();
			Console.Write("Decrypting testfile . . .\n");
			await
				Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey,
					Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
					testfileDecryptedOutputDirectory, progressDecrypt);
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

		/// <summary>
		///     Self encrypt and decrypt a small file async.
		/// </summary>
		[Test]
		public async Task WorkWithSmallFileTesAsynct()
		{
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "verysmallfile.dat");
			var testfileDecryptedFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted",
				"verysmallfile.dat");
			var testfileDecryptedOutputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles",
				"decrypted");
			const string outputDirectory = "Testfiles";
			const long testfileSizeKb = 1024;
			const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
			var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Console.Write("Generating {0} KB testfile . . .\n", testfileSizeKb);
			var fs = new FileStream(testfileRaw, FileMode.CreateNew);
			fs.Seek(testfileSizeKb*1024, SeekOrigin.Begin);
			fs.WriteByte(0);
			fs.Close();
			Console.Write("Encrypting testfile . . .\n");
			var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair, testfileRaw, progressEncrypt);
			Console.Write("Decrypting testfile . . .\n");
			await
				Cryptor.DecryptFileWithStreamAsync(keyPair,
					Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
					testfileDecryptedOutputDirectory, progressDecrypt);
			Console.Write("Get checksum of testfiles . . .\n");
			Assert.AreEqual(Utils.GetChecksum(testfileRaw), Utils.GetChecksum(testfileDecryptedFile));
			//clear garbage 
			File.Delete(testfileRaw);
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
			File.Delete(testfileDecryptedFile);
		}

		/// <summary>
		///     Encrypt a file from a stream.
		/// </summary>
		[Test]
		public async Task WorkWithStreamTestAsync()
		{
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
			var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
			var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
			var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			var data = File.ReadAllBytes(rawFile);
			var stream = new MemoryStream(data);
			Console.Write("Encrypting MemoryStream . . .\n");
			var encryptedFile =
				await
					Cryptor.EncrypMemoryStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
						Utilities.HexToBinary(publicKey), "MyAwesomeChipmunkKiller.jpg", stream, outputDirectory, ".test", true,
						progressEncrypt).ConfigureAwait(false);
			Console.Write("Decrypting testfile (" + encryptedFile + ") . . .\n");
			var decryptedFileObject =
				await
					Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(outputDirectory, encryptedFile),
						progressDecrypt).ConfigureAwait(false);

			Console.Write("Get checksum of testfiles . . .\n");
			Assert.AreEqual(Utils.GetChecksum(rawFile), Utils.GetChecksum(decryptedFileObject.FileData));
			//clear garbage 
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
		}

		/// <summary>
		///     Encrypt a file from a stream.
		/// </summary>
		[Test]
		public async Task WorkWithStreamTestSmallAsync()
		{
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };

			const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
			var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
			var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));

			var TESTFILE_RAW = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "verysmallfile.dat");
			const long TESTFILE_SIZE_KB = 1;

			Console.Write("Generating {0} KB testfile . . .\n", TESTFILE_SIZE_KB);
			var fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
			fs.Seek(TESTFILE_SIZE_KB*1024, SeekOrigin.Begin);
			fs.WriteByte(0);
			fs.Close();

			var data = File.ReadAllBytes(TESTFILE_RAW);
			var stream = new MemoryStream(data);
			Console.Write("Encrypting MemoryStream . . .\n");
			var encryptedFile =
				await
					Cryptor.EncrypMemoryStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
						Utilities.HexToBinary(publicKey), TESTFILE_RAW, stream, outputDirectory, ".test", true, progressEncrypt)
						.ConfigureAwait(false);

			Console.Write("Decrypting testfile (" + encryptedFile + ") . . .\n");
			var decryptedFileObject =
				await
					Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(outputDirectory, encryptedFile),
						progressDecrypt).ConfigureAwait(false);
			Console.Write("Get checksum of testfiles . . .\n");
			Assert.AreEqual(Utils.GetChecksum(TESTFILE_RAW), Utils.GetChecksum(decryptedFileObject.FileData));
			//clear garbage 
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
			File.Delete(TESTFILE_RAW);
		}

		/// <summary>
		///     Self encrypt and decrypt a very small file async.
		/// </summary>
		[Test]
		public async Task WorkWithVerySmallFileTestAsync()
		{
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n"); };
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "verysmallfile.dat");
			var testfileDecryptedFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted",
				"verysmallfile.dat");
			var testfileDecryptedOutputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles",
				"decrypted");
			const string outputDirectory = "Testfiles";
			const long testfileSizeKb = 1;
			const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
			var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Console.Write("Generating {0} KB testfile . . .\n", testfileSizeKb);
			var fs = new FileStream(testfileRaw, FileMode.CreateNew);
			fs.Seek(testfileSizeKb*1024, SeekOrigin.Begin);
			fs.WriteByte(0);
			fs.Close();
			Console.Write("Encrypting testfile . . .\n");
			var encryptedFile = await Cryptor.EncryptFileWithStreamAsync(keyPair, testfileRaw, progressEncrypt);
			Console.Write("Decrypting testfile . . .\n");
			await
				Cryptor.DecryptFileWithStreamAsync(keyPair,
					Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile),
					testfileDecryptedOutputDirectory, progressDecrypt);
			Console.Write("Get checksum of testfiles . . .\n");
			Assert.AreEqual(Utils.GetChecksum(testfileRaw), Utils.GetChecksum(testfileDecryptedFile));
			//clear garbage 
			File.Delete(testfileRaw);
			File.Delete(Path.Combine(TestContext.CurrentContext.TestDirectory, outputDirectory, encryptedFile));
			File.Delete(testfileDecryptedFile);
		}
	}
}