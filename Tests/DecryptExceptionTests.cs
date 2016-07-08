using System;
using System.IO;
using NUnit.Framework;
using Sodium;
using StreamCryptor;

namespace Tests
{
	/// <summary>
	///     Validate the Decrypt* parameters.
	/// </summary>
	[TestFixture]
	public class DecryptExceptionTests
	{
		[Test]
		public void DecryptioInvalidPrivateKeyInPairTest()
		{
			const string privateKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.Throws<ArgumentOutOfRangeException>(
				() => { Cryptor.DecryptFileWithStream(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted")); });
		}

		[Test]
		public void DecryptioInvalidPrivateKeyTest()
		{
			const string privateKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			Assert.Throws<ArgumentOutOfRangeException>(
				() =>
				{
					Cryptor.DecryptFileWithStream(Utilities.HexToBinary(privateKey), "badfile",
						Path.Combine("Testfiles", "decrypted"));
				});
		}

		[Test]
		public void DecryptioInvalidPublicKeyInPairTest()
		{
			const string privateKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.Throws<ArgumentOutOfRangeException>(
				() => { Cryptor.DecryptFileWithStream(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted")); });
		}

		[Test]
		public void DecryptionInputFileNotFoundTest()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.Throws<FileNotFoundException>(
				() => { Cryptor.DecryptFileWithStream(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted")); });
		}

		[Test]
		public void DecryptionOutputFolderNotFoundTest()
		{
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.Throws<DirectoryNotFoundException>(
				() => { Cryptor.DecryptFileWithStream(testKeyPair, testfileRaw, "badfolder"); });
		}
	}
}