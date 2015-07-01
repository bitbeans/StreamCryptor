using System;
using NUnit.Framework;
using Sodium;
using StreamCryptor.Helper;

namespace Tests
{
    [TestFixture]
    public class UtilitieTests
    {
        /// <summary>
        ///     Check GetEphemeralEncryptionKey() for the correct output.
        /// </summary>
        [Test]
        public void GetEphemeralEncryptionKeyTest()
        {
            const string expectedEphemeralKeyHex =
                "e8b53184264ccb26b94bcf7e0be77d62a1304f49c6ebc21a3ca6a4614cd7cdba09355e5fe263d2934d8cbad4f8207c9ef6dd6d81dd4f6f668e7c33dedf7cce11";
            const string expectedEphemeralEncryptionKeyHex =
                "e8b53184264ccb26b94bcf7e0be77d62a1304f49c6ebc21a3ca6a4614cd7cdba";
            var expectedEphemeralKeyBin = Utilities.HexToBinary(expectedEphemeralKeyHex);
            Assert.AreEqual(expectedEphemeralEncryptionKeyHex,
                Utilities.BinaryToHex(Utils.GetEphemeralEncryptionKey(expectedEphemeralKeyBin)));
        }

        /// <summary>
        ///     Check GetEphemeralHashKey() for the correct output.
        /// </summary>
        [Test]
        public void GetEphemeralHashKeyTest()
        {
            const string expectedEphemeralKeyHex =
                "e8b53184264ccb26b94bcf7e0be77d62a1304f49c6ebc21a3ca6a4614cd7cdba09355e5fe263d2934d8cbad4f8207c9ef6dd6d81dd4f6f668e7c33dedf7cce11";
            const string expectedEphemeralHashKeyHex =
                "09355e5fe263d2934d8cbad4f8207c9ef6dd6d81dd4f6f668e7c33dedf7cce11";
            var expectedEphemeralKeyBin = Utilities.HexToBinary(expectedEphemeralKeyHex);
            Assert.AreEqual(expectedEphemeralHashKeyHex,
                Utilities.BinaryToHex(Utils.GetEphemeralHashKey(expectedEphemeralKeyBin)));
        }

        /// <summary>
        ///     Check GetRandomFileName() for the correct output length.
        /// </summary>
        [Test]
        public void GenerateRandomFileNameTest()
        {
            const string fileExtension = ".sccef";
            const int randomStringLength = 11;
            for (var i = 10; i > 0; i--)
            {
                var randomString = Utils.GetRandomFileName(randomStringLength, fileExtension);
                Console.WriteLine("Generated random filename " + randomString + " with length of " + (randomStringLength + fileExtension.Length) +
                                  " chars");
                Assert.AreEqual(randomString.Length, randomStringLength + fileExtension.Length);
            }
        }

        /// <summary>
        ///     Check ConcatArrays() for the correct output.
        /// </summary>
        [Test]
        public void ConcatenateArraysTest()
        {
            var expectedArray = new byte[]
            {
                159, 5, 128, 251, 11, 77, 77, 217,
                134, 151, 2, 63, 29, 180, 56, 81,
                35, 169, 179, 238, 245, 42, 215, 129,
                56, 217, 10, 203, 68, 152, 208, 5,
                189, 245, 218, 9, 163, 240, 185, 114,
                205, 33, 6, 23, 155, 103, 139, 216,
                98, 35, 143, 69, 5, 59, 170, 236,
                93, 33, 51, 75, 222, 220, 195, 69
            };

            var array1 = new byte[]
            {
                159, 5, 128, 251, 11, 77, 77, 217,
                134, 151, 2, 63, 29, 180, 56, 81,
                35, 169, 179, 238, 245, 42, 215, 129,
                56, 217, 10, 203, 68, 152, 208, 5
            };

            var array2 = new byte[]
            {
                189, 245, 218, 9, 163, 240, 185, 114,
                205, 33, 6, 23, 155, 103, 139, 216,
                98, 35, 143, 69, 5, 59, 170, 236,
                93, 33, 51, 75, 222, 220, 195, 69
            };

            var concatenatedArrays = ArrayHelpers.ConcatArrays(array1, array2);
            Assert.AreEqual(expectedArray, concatenatedArrays);
        }
    }
}