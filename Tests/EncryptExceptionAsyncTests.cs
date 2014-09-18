using NUnit.Framework;
using Sodium;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tests
{
    /// <summary>
    /// Validate the Encrypt*Async parameters.
    /// </summary>
    [TestFixture]
    public class EncryptExceptionAsyncTests
    {
        [Test]
        [ExpectedException(typeof(FileNotFoundException))]
        public async void EncryptionInputFileNotFoundTestAsync()
        {
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(NullReferenceException))]
        public async void EncryptionNoPrivateKeyInPairTestAsync()
        {
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), null);
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(NullReferenceException))]
        public async void EncryptionNoPublicKeyInPairTestAsync()
        {
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(null, Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionNoPrivateKeyTestAsync()
        {
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync((byte[])null, Utilities.HexToBinary(PUBLIC_KEY), (byte[])null, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionNoPublicKeyTestAsync()
        {
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(Utilities.HexToBinary(PRIVATE_KEY), (byte[])null, (byte[])null, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionNoRecipientPublicKeyTestAsync()
        {
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(Utilities.HexToBinary(PRIVATE_KEY), Utilities.HexToBinary(PUBLIC_KEY), (byte[])null, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionInvalidPrivateKeyInPairTestAsync()
        {
            string PRIVATE_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionInvalidPublicKeyInPairTestAsync()
        {
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(DirectoryNotFoundException))]
        public async void EncryptionOutputFolderNotFoundTestAsync()
        {
            const string TESTFILE_RAW = "Testfiles\\MyAwesomeChipmunkKiller.jpg";
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(testKeyPair, TESTFILE_RAW, null, "badfolder");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionBadFileExtensionTestAsync()
        {
            const string TESTFILE_RAW = "Testfiles\\MyAwesomeChipmunkKiller.jpg";
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(testKeyPair, TESTFILE_RAW, null, "Testfiles\\decrypted", "hulk");
        }
    }
}
