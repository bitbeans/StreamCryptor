```csharp
//Some example
private async void buttomStartDemo_Click(object sender, EventArgs e)
{
	const string TESTFILE_RAW = "1GB.dat";
	Assembly ass = Assembly.GetExecutingAssembly();
	string path = System.IO.Path.GetDirectoryName(ass.Location);

	FileStream fs = new FileStream(TESTFILE_RAW, FileMode.CreateNew);
	fs.Seek(1024 * 1024 * 1024, SeekOrigin.Begin);
	fs.WriteByte(0);
	fs.Close();

	Sodium.KeyPair k = new Sodium.KeyPair();
	k = Sodium.PublicKeyBox.GenerateKeyPair();
	string encryptedFile = await EncryptAsync(k, TESTFILE_RAW);
	File.Delete(TESTFILE_RAW);
	string decryptedFile = await DecryptAsync(k, encryptedFile, path);

	File.Delete(encryptedFile);
	File.Delete(decryptedFile);
}

async Task<string> EncryptAsync(Sodium.KeyPair keyPair, string file)
{
	var encryptionProgress = new Progress<StreamCryptorTaskAsyncProgress>();
	encryptionProgress.ProgressChanged += (s, e) =>
	{
		progressBarEncryption.Value = e.ProgressPercentage;
		textBoxEncryption.Text = e.ProgressPercentage.ToString();
	};
	return await StreamCryptor.StreamCryptor.EncryptFileWithStreamAsync(keyPair.PrivateKey, keyPair.PublicKey, keyPair.PublicKey, file, encryptionProgress);
}

async Task<string> DecryptAsync(Sodium.KeyPair keyPair, string file, string outputFolder)
{
	var decryptionProgress = new Progress<StreamCryptorTaskAsyncProgress>();
	decryptionProgress.ProgressChanged += (s, e) =>
	{
		progressBarDecryption.Value = e.ProgressPercentage;
		textBoxDecryption.Text = e.ProgressPercentage.ToString();
	};
	return await StreamCryptor.StreamCryptor.DecryptFileWithStreamAsync(keyPair.PrivateKey, file, outputFolder, decryptionProgress);
}	
```