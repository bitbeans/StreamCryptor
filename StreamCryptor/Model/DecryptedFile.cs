namespace StreamCryptor.Model
{
    /// <summary>
    ///     Represents a decrypted file.
    /// </summary>
    public class DecryptedFile
    {
        /// <summary>
        ///     Holds the decrypted data.
        /// </summary>
        public byte[] FileData { get; set; }

        /// <summary>
        ///     The decrypted file name.
        /// </summary>
        public string FileName { get; set; }

        /// <summary>
        ///     The length of the decrypted file.
        /// </summary>
        public long FileSize { get; set; }
    }
}