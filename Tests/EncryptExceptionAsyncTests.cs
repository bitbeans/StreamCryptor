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
	///     Validate the Encrypt*Async parameters.
	/// </summary>
	[TestFixture]
	public class EncryptExceptionAsyncTests
	{
		[Test]
		public void EncryptionBadFileExtensionTestAsync()
		{
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(
				async () => await
					Cryptor.EncryptFileWithStreamAsync(testKeyPair, testfileRaw, null,
						Path.Combine("Testfiles", "decrypted"), "hulk"));
		}

		[Test]
		public void EncryptionCancellationTestAsync()
		{
			var cancellationTokenSource = new CancellationTokenSource();
			var progressEncrypt = new Progress<StreamCryptorTaskAsyncProgress>();
			progressEncrypt.ProgressChanged +=
				(s, e) =>
				{
					if (e.ProgressPercentage > 10)
					{
						cancellationTokenSource.Cancel();
					}
					Console.WriteLine("Encrypting: " + e.ProgressPercentage + "%\n");
				};

			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";

			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<TaskCanceledException>(async () => await
				Cryptor.EncryptFileWithStreamAsync(testKeyPair, testfileRaw, progressEncrypt,
					Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "decrypted"), ".sccef",
					cancellationToken: cancellationTokenSource.Token));
		}

		[Test]
		public void EncryptionInputFileNotFoundTestAsync()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<FileNotFoundException>(
				async () => await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile"));
		}

		[Test]
		public void EncryptionInvalidPrivateKeyInPairTestAsync()
		{
			const string privateKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(
				async () => await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile"));
		}

		[Test]
		public void EncryptionInvalidPublicKeyInPairTestAsync()
		{
			var privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var publicKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(
				async () => await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile"));
		}

		[Test]
		public void EncryptionNoPrivateKeyTestAsync()
		{
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(
				async () => await Cryptor.EncryptFileWithStreamAsync(null, Utilities.HexToBinary(publicKey), null, "badfile"));
		}

		[Test]
		public void EncryptionNoPublicKeyInPairTestAsync()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(null, Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<NullReferenceException>(
				async () => await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile"));
		}

		[Test]
		public void EncryptionNoPublicKeyTestAsync()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(
				async () => await Cryptor.EncryptFileWithStreamAsync(Utilities.HexToBinary(privateKey), null, null, "badfile"));
		}

		[Test]
		public void EncryptionNoRecipientPublicKeyTestAsync()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			Assert.ThrowsAsync<ArgumentOutOfRangeException>(
				async () => await
					Cryptor.EncryptFileWithStreamAsync(Utilities.HexToBinary(privateKey), Utilities.HexToBinary(publicKey),
						null, "badfile"));
		}

		[Test]
		public void EncryptionOutputFolderNotFoundTestAsync()
		{
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.ThrowsAsync<DirectoryNotFoundException>(
				async () => await Cryptor.EncryptFileWithStreamAsync(testKeyPair, testfileRaw, null, "badfolder"));
		}
	}
}