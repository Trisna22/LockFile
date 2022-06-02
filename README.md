# LockFile

Encrypts/decrypts files on local computer with custom combination of encryption methods. Every file in a folder gets an own key so bruteforcing all files is harder. Make sure to not forget your password or else your data will be gone for good. Your unencrypted files can be shredded if needed.

## Installing project
```bash
$ git clone https://github.com/Trisna22/LockFile
$ cd LockFile
$ make
$ sudo cp ./build/LockFile /usr/bin
$ LockFile --help
```

## Usage
```bash
# For encrypting files/folders
$ LockFile --encrypt folderToEncrypt
# For decrypting files/folders
$ LockFile --decrypt folderToDecrypt
# To get information of any CryptFile
$ LockFile --info cryptFile
```

 ## CryptFile architecture
```xml
<File>
<CryptHeader/>
    <RSA-Encrypted>
        <CryptFile-object>
        <CryptFile-object>
        <CryptFile-object>
        ...
    </RSA-Encrypted>
    <AES-Encrypted>
        <FileData>
        ...
    </AES-Encrypted>
</File>
```
## CryptFile object
The CryptFile object contain information of the encrypted files. Every file has his own key and IV for the AES encryption.  
The objects won't be visible without your provided password, the objects itself are encrypted with RSA.

```C++
struct CryptFile {
       int fileNameLen;                // The size of the filename.
       bool isFolder;                  // Is folder?
       unsigned long sizeFileData;     // File data size.
       unsigned char fileKey[32];      // The key of the AES encryption.
       unsigned char fileIV[16];       // The IV of the AES encryption.
       unsigned char fileHash[16];     // The hash of the (unencrypted) content.
       char *fileName;                 // Filename.
};
```

## Used libraries
OpenSSL [https://www.openssl.org/]  
pthreads [https://man7.org/linux/man-pages/man7/pthreads.7.html]

## TODO
```
- [X] Section encryption/decryption.
- [X] Use sendfile() function for better performance
- [X] RSA stream encrypt instead of blocks of data
- [X] File shredder for deleting files
- [X] Improve the AES encryption, write memory-based encryption.
- [~] Create a TUI (Terminal User Interface) animation?
- [ ] Threads for better performance
- [ ] Save file permissions in CryptFile. (Read-Write-Execute)
- [ ] Compression algorithm
- [ ] -r option to auto delete the original files with our shredder
- [ ] Adding own MIME and file extension
```

## Credits
Me, Myself and I
