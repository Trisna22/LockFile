# LockFile

Encrypts/decrypts files on local computer with custom combination of encryption methods. Every file in a folder gets an own key so bruteforcing all files is harder. Make sure to not forget your password or else your data will be gone for good. Your unencrypted files can be shredded if needed.

## Install and usage
```bash
cd LockFile
make
sudo cp ./build/LockFile /usr/bin
LockFile --help
```

## TODO
```
- [X] Section encryption/decryption.
- [ ] Create a TUI (Terminal User Interface) animation?
- [ ] Threads for better performance
- [X] Use sendfile() function for better performance?
- [X] RSA stream encrypt instead of blocks of data
- [X] File shredder for the .enc files.
- [ ] Save file permissions in CryptFile. (Read-Write-Execute)
- [ ] Improve the AES encryption, write memory-based encryption.
- [ ] Compression algorithm
- [ ] -r option to auto delete the original files with our shredder
```

## Bugs
 ``` 
- When you' re encrypting in one folder, it loops trough the .enc files too, so
 it will generate FILE.txt.enc -> FILE.txt.enc.enc -> FILE.txt.enc.enc.enc until the filename is too big. This can be fixed by exiting the loop shorthand or check the file count in the folder and loop that count only.
 ```

 ## CryptFile architecture
```xml
<File>
<CryptHeader>
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

## Used libraries
OpenSSL [https://www.openssl.org/]  
pthreads [https://man7.org/linux/man-pages/man7/pthreads.7.html]

## Credits
Me, Myself and I
