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
    /// Validate the Decrypt*Async parameters.
    /// </summary>
    [TestFixture]
    public class DecryptExceptionAsyncTests
    {
        [Test]
        [ExpectedException(typeof(FileNotFoundException))]
        public async void DecryptionInputFileNotFoundTestAsync()
        {
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", "Testfiles\\decrypted");
        }

        [Test]
        [ExpectedException(typeof(NullReferenceException))]
        public async void DecryptionNoPrivateKeyInPairTestAsync()
        {
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), null);
            await StreamCryptor.StreamCryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", "Testfiles\\decrypted");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void DecryptioInvalidPrivateKeyInPairTestAsync()
        {
            string PRIVATE_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", "Testfiles\\decrypted");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void DecryptioInvalidPublicKeyInPairTestAsync()
        {
            string PRIVATE_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", "Testfiles\\decrypted");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public async void DecryptioInvalidPrivateKeyTestAsync()
        {
            string PRIVATE_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            await StreamCryptor.StreamCryptor.DecryptFileWithStreamAsync(Utilities.HexToBinary(PRIVATE_KEY), "badfile", "Testfiles\\decrypted");
        }

        [Test]
        [ExpectedException(typeof(DirectoryNotFoundException))]
        public async void DecryptionOutputFolderNotFoundTestAsync()
        {
            const string TESTFILE_RAW = "Testfiles\\MyAwesomeChipmunkKiller.jpg";
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await StreamCryptor.StreamCryptor.DecryptFileWithStreamAsync(testKeyPair, TESTFILE_RAW, "badfolder");
        }
    }
}
