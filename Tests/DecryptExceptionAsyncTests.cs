using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using Sodium;
using StreamCryptor;
using StreamCryptor.Model;

namespace Tests
{
	/// <summary>
	///     Validate the Decrypt*Async parameters.
	/// </summary>
	[TestFixture]
	public class DecryptExceptionAsyncTests
	{
		[Test]
		public void DecryptioInvalidPrivateKeyInPairTestAsync()
		{
			const string privateKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(
				async () => await Cryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted")));
		}

		[Test]
		public void DecryptioInvalidPrivateKeyTestAsync()
		{
			const string privateKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await
				Cryptor.DecryptFileWithStreamAsync(Utilities.HexToBinary(privateKey), "badfile",
					Path.Combine("Testfiles", "decrypted")));
		}

		[Test]
		public void DecryptioInvalidPublicKeyInPairTestAsync()
		{
			const string privateKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(
				async () => await Cryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted")));
		}

		[Test]
		public void DecryptionCancellationTestAsync()
		{
			var cancellationTokenSource = new CancellationTokenSource();
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			var progressDecrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) => { Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n"); };
			progressDecrypt.ProgressChanged +=
				(s, e) =>
				{
					if (e.ProgressPercentage > 10)
					{
						cancellationTokenSource.Cancel();
					}
					Console.WriteLine("Decrypting: " + e.ProgressPercentage + "%\n");
				};
			var rawFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			var outputDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted");
			const string privateKey = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
			const string publicKey = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
			var keyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Console.Write("Encrypting testfile . . .\n");
			var encryptedFile = Cryptor.EncryptFileWithStream(keyPair.PrivateKey, keyPair.PublicKey,
				Utilities.HexToBinary(publicKey), rawFile, outputDirectory, ".test", true);
			Console.Write("Decrypting testfile . . .\n");
			Assert.ThrowsAsync<TaskCanceledException>(async () => await
				Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(outputDirectory, encryptedFile),
					outputDirectory, progressDecrypt, cancellationToken: cancellationTokenSource.Token));
		}

		[Test]
		public void DecryptionInputFileNotFoundTestAsync()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<FileNotFoundException>(
				async () => await Cryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted")));
		}

		[Test]
		public void DecryptionOutputFolderNotFoundTestAsync()
		{
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<DirectoryNotFoundException>(
				async () => await Cryptor.DecryptFileWithStreamAsync(testKeyPair, testfileRaw, "badfolder"));
		}
	}
}