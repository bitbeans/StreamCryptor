# StreamCryptor [![Build status](https://ci.appveyor.com/api/projects/status/73fb5hecxx9xjyip)](https://ci.appveyor.com/project/bitbeans/streamcryptor)
StreamCryptor uses `FileStream` to encrypt and decrypt files in chunks. Every file contains a `EncryptedFileHeader` and some `EncryptedFileChunks`. The file serialization is realised with Google`s protobuf, it has a small overhead and offers an automatic length prefix for all file parts.

All cryptographic operations are performed via [libsodium](https://github.com/jedisct1/libsodium).


## Status

Project is under development!

:facepunch: Don`t use this code in a live project!

:bug: It could contain bugs.

:bangbang: The concept is maybe a failure!

## This project uses the following libraries

  * [libsodium-net] - A secure cryptographic library
  * [protobuf-net] - Efficient binary serialization by Google


[libsodium-net]:https://github.com/adamcaudill/libsodium-net
[protobuf-net]:https://code.google.com/p/protobuf-net/

## Usage

### Methods

`public static void EncryptFileWithStream(KeyPair keyPair, string inputFile, bool maskFileName = false)`

`public static void EncryptFileWithStream(KeyPair keyPair, string inputFile, string outputFolder, bool maskFileName = false)`

`public static void DecryptFileWithStream(KeyPair keyPair, string inputFile, string outputFolder)`

### And some fixed parameters
```
private const int CHUNK_LENGTH = 1048576; //~1MB
private const int CHUNK_COUNT_START = 0;
private const int CHUNK_CHECKSUM_LENGTH = 64;
private const int MIN_CHUNK_NUMBER = 0;
private const int NONCE_LENGTH = 24;
private const int BASE_NONCE_LENGTH = 16;
private const int CURRENT_VERSION = 1;
private const int MIN_VERSION = 1;
private const int HEADER_CHECKSUM_LENGTH = 64;
private const int MAX_FILENAME_LENGTH = 256;
private const int MASKED_FILENAME_LENGTH = 11;
private const string DEFAULT_FILE_EXTENSION = ".encrypted";
```

## Help wanted
See bitbeans/StreamCryptor#3

## Why
Inspired by jedisct1/libsodium.js#141 and the [nacl-stream-js](https://github.com/dchest/nacl-stream-js) project.

## License
[MIT](https://en.wikipedia.org/wiki/MIT_License)
