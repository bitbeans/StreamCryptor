using NUnit.Framework;
using Sodium;
using System.IO;

namespace Tests
{
    [TestFixture]
    public class CryptoStreamTests
    {
        /// <summary>
        ///
        ///</summary>
        [Test]
        public void CryptoStreamTest()
        {
            const string RAW_FILE = "Testfiles\\MyAwesomeChipmunkKiller.jpg";
            const string ENCRYPTED_FILE = "Testfiles\\MyAwesomeChipmunkKiller.enc";
            const string DECRYPTED_FILE = "Testfiles\\MyAwesomeChipmunkKiller_.jpg";
            string PRIVATE_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            string PUBLIC_KEY = "1158b1ea7d45919968b87dab6cab27eff5871304ea9856588e9ec02a6d93c42e";
            KeyPair keyPair = new KeyPair(Utilities.HexToBinary(PUBLIC_KEY), Utilities.HexToBinary(PRIVATE_KEY));

            StreamCryptor.StreamCryptor.EncryptFileWithStream(keyPair, RAW_FILE, ENCRYPTED_FILE);
            StreamCryptor.StreamCryptor.DecryptFileWithStream(keyPair, ENCRYPTED_FILE, DECRYPTED_FILE);

            if (File.Exists(DECRYPTED_FILE))
            {
                //FIXME: test should check file checksum
                FileInfo rawInfo = new FileInfo(RAW_FILE);
                long s1 = rawInfo.Length;

                FileInfo decryptedInfo = new FileInfo(DECRYPTED_FILE);
                long s2 = decryptedInfo.Length;

                Assert.AreEqual(s1, s2);
            }

            //clear garbage 
            File.Delete(ENCRYPTED_FILE);
            File.Delete(DECRYPTED_FILE);
        }
    }
}
