using System;
using System.IO;
using System.Threading;
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
        [ExpectedException(typeof (FileNotFoundException))]
        public async void DecryptionInputFileNotFoundTestAsync()
        {
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof (NullReferenceException))]
        public async void DecryptionNoPrivateKeyInPairTestAsync()
        {
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), null);
            await Cryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof (ArgumentOutOfRangeException))]
        public async void DecryptioInvalidPrivateKeyInPairTestAsync()
        {
            const string PRIVATE_KEY =
                "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof (ArgumentOutOfRangeException))]
        public async void DecryptioInvalidPublicKeyInPairTestAsync()
        {
            const string PRIVATE_KEY =
                "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.DecryptFileWithStreamAsync(testKeyPair, "badfile", Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof (ArgumentOutOfRangeException))]
        public async void DecryptioInvalidPrivateKeyTestAsync()
        {
            const string PRIVATE_KEY =
                "863df54207c285feac2c22235c336869fee8dba6605b8e1bc45cc8aa5e1be3fd7e53781865717d686cb3fee427823ffd8c71ea6a4d8f79c0b410457c9f881fa3";
            await
                Cryptor.DecryptFileWithStreamAsync(Utilities.HexToBinary(PRIVATE_KEY), "badfile",
                    Path.Combine("Testfiles", "decrypted"));
        }

        [Test]
        [ExpectedException(typeof (DirectoryNotFoundException))]
        public async void DecryptionOutputFolderNotFoundTestAsync()
        {
            var TESTFILE_RAW = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            const string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            const string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            var testKeyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            await Cryptor.DecryptFileWithStreamAsync(testKeyPair, TESTFILE_RAW, "badfolder");
        }

        [Test]
        [ExpectedException(typeof(OperationCanceledException))]
        public async void DecryptionCancellationTestAsync()
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
            var RAW_FILE = Path.Combine("Testfiles", "MyAwesomeChipmunkKiller.jpg");
            var OUTPUT_DIRECTORY = Path.Combine("Testfiles", "decrypted");
            const string PRIVATE_KEY = "31d9040b00a170532929b37db0afcb989e4175f96e5f9667ee8cbf5706679a71";
            const string PUBLIC_KEY = "6d0deec730700f9f60687a4e6e8755157ca22ea2f3815b9bf14b1fe9ae6a0b4d";
            var keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));
            Console.Write("Encrypting testfile . . .\n");
            var encryptedFile =
                await
                    Cryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey,
                        Utilities.HexToBinary(PUBLIC_KEY), RAW_FILE, progressEncrypt, OUTPUT_DIRECTORY, ".test", true, cancellationTokenSource.Token);
            Console.Write("Decrypting testfile . . .\n");
            var decryptedFile =
                await
                    Cryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, Path.Combine(OUTPUT_DIRECTORY, encryptedFile),
                        OUTPUT_DIRECTORY, progressDecrypt, cancellationToken: cancellationTokenSource.Token);

        }
    }
}