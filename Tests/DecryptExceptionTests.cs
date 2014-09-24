using NUnit.Framework;
using Sodium;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using StreamCryptor;

namespace Tests
{
    /// <summary>
    /// Validate the Decrypt* parameters.
    /// </summary>
    [TestFixture]
    public class DecryptExceptionTests
    {
        [Test]
        [ExpectedException(typeof(FileNotFoundException))]
        public void DecryptionInputFileNotFoundTest()
        {
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Cryptor.DecryptFileWithStream(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof(NullReferenceException))]
        public void DecryptionNoPrivateKeyInPairTest()
        {
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), null);
            Cryptor.DecryptFileWithStream(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void DecryptioInvalidPrivateKeyInPairTest()
        {
            const string PRIVATE_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Cryptor.DecryptFileWithStream(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void DecryptioInvalidPublicKeyInPairTest()
        {
            const string PRIVATE_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Cryptor.DecryptFileWithStream(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void DecryptioInvalidPrivateKeyTest()
        {
            const string PRIVATE_KEY = "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            Cryptor.DecryptFileWithStream(Utilities.HexToBinary(PRIVATE_KEY), "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof(DirectoryNotFoundException))]
        public void DecryptionOutputFolderNotFoundTest()
        {
            string TESTFILE_RAW = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Cryptor.DecryptFileWithStream(testKeyPair, TESTFILE_RAW, "badfolder");
        }
    }
}
