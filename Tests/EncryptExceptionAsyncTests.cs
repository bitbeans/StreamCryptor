using NUnit.Framework;
using Sodium;
using StreamCryptor;
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
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(NullReferenceException))]
        public async void EncryptionNoPrivateKeyInPairTestAsync()
        {
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), null);
            await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(NullReferenceException))]
        public async void EncryptionNoPublicKeyInPairTestAsync()
        {
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(null, Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionNoPrivateKeyTestAsync()
        {
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            await Cryptor.EncryptFileWithStreamAsync((byte[])null, Utilities.HexToBinary(PUBLIC_KEY), (byte[])null, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionNoPublicKeyTestAsync()
        {
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            await Cryptor.EncryptFileWithStreamAsync(Utilities.HexToBinary(PRIVATE_KEY), (byte[])null, (byte[])null, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionNoRecipientPublicKeyTestAsync()
        {
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            await Cryptor.EncryptFileWithStreamAsync(Utilities.HexToBinary(PRIVATE_KEY), Utilities.HexToBinary(PUBLIC_KEY), (byte[])null, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionInvalidPrivateKeyInPairTestAsync()
        {
            const string PRIVATE_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionInvalidPublicKeyInPairTestAsync()
        {
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.EncryptFileWithStreamAsync(testKeyPair, "badfile");
        }

        [Test]
        [ExpectedException(typeof(DirectoryNotFoundException))]
        public async void EncryptionOutputFolderNotFoundTestAsync()
        {
            string TESTFILE_RAW = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.EncryptFileWithStreamAsync(testKeyPair, TESTFILE_RAW, null, "badfolder");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void EncryptionBadFileExtensionTestAsync()
        {
            string TESTFILE_RAW = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.EncryptFileWithStreamAsync(testKeyPair, TESTFILE_RAW, null, Path.Combine("Testfiles", "decrypted"), "hulk");
        }
    }
}
