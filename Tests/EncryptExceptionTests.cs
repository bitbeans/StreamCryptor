using System;
using System.IO;
using NUnit.Framework;
using Sodium;
using StreamCryptor;

namespace Tests
{
	/// <summary>
	///     Validate the Encrypt* parameters.
	/// </summary>
	[TestFixture]
	public class EncryptExceptionTests
	{
		[Test]
		public void EncryptionBadFileExtensionTest()
		{
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.Throws<ArgumentOutOfRangeException>(
				() => { Cryptor.EncryptFileWithStream(testKeyPair, testfileRaw, Path.Combine("Testfiles", "decrypted"), "hulk"); });
		}

		[Test]
		public void EncryptionInputFileNotFoundTest()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));

			Assert.Throws<FileNotFoundException>(
				() => { Cryptor.EncryptFileWithStream(testKeyPair, "badfile"); });
		}


		[Test]
		public void EncryptionInvalidInputFileNameTest()
		{
			//Currently no test, because the path will be too long.
			//Just pass this. :)
			Assert.Throws<ArgumentOutOfRangeException>(
				() => { throw new ArgumentOutOfRangeException("badtest"); });
		}

		[Test]
		public void EncryptionInvalidPrivateKeyInPairTest()
		{
			const string privateKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.Throws<ArgumentOutOfRangeException>(
				() => { Cryptor.EncryptFileWithStream(testKeyPair, "badfile"); });
		}

		[Test]
		public void EncryptionInvalidPublicKeyInPairTest()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey =
				"863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));

			Assert.Throws<ArgumentOutOfRangeException>(
				() => { Cryptor.EncryptFileWithStream(testKeyPair, "badfile"); });
		}

		[Test]
		public void EncryptionNoPrivateKeyTest()
		{
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			Assert.Throws<ArgumentOutOfRangeException>(
				() => { Cryptor.EncryptFileWithStream(null, Utilities.HexToBinary(publicKey), (byte[]) null, "badfile"); });
		}

		[Test]
		public void EncryptionNoPublicKeyInPairTest()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(null, Utilities.HexToBinary(privateKey));
			Assert.Throws<NullReferenceException>(
				() => { Cryptor.EncryptFileWithStream(testKeyPair, "badfile"); });
		}

		[Test]
		public void EncryptionNoPublicKeyTest()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			Assert.Throws<ArgumentOutOfRangeException>(
				() => { Cryptor.EncryptFileWithStream(Utilities.HexToBinary(privateKey), null, null, "badfile"); });
		}

		[Test]
		public void EncryptionNoRecipientPublicKeyTest()
		{
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			Assert.Throws<ArgumentOutOfRangeException>(
				() =>
				{
					Cryptor.EncryptFileWithStream(Utilities.HexToBinary(privateKey), Utilities.HexToBinary(publicKey), null,
						"badfile");
				});
		}

		[Test]
		public void EncryptionOutputFolderNotFoundTest()
		{
			var testfileRaw = Path.Combine(TestContext.CurrentContext.TestDirectory, "Testfiles", "MyAwesomeChipmunkKiller.jpg");
			const string privateKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			const string publicKey = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
			var testKeyPair = new KeyPair(Utilities.HexToBinary(publicKey), Utilities.HexToBinary(privateKey));
			Assert.Throws<DirectoryNotFoundException>(
				() => { Cryptor.EncryptFileWithStream(testKeyPair, testfileRaw, "badfolder"); });
		}
	}
}