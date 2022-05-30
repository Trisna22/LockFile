# LockFile

Encrypts/decrypts files on local computer with custom combination of encryption methods.  

## TODO
```
- [X] Section encryption/decryption.
- [ ] Create a TUI (Terminal User Interface) animation?
- [ ] Threads for better performance
- [~] Use sendfile() function for better performance?
- [X] RSA stream encrypt instead of blocks of data
- [X] File shredder for the .enc files.
- [ ] Save file permissions in CryptFile. (Read-Write-Execute)
- [ ] Improve the AES encryption, write memory-based encryption.
- [ ] Compression algorithm
```

## Bugs
 ``` 
- When you' re encrypting in one folder, it loops trough the .enc files too, so
 it will generate FILE.txt.enc -> FILE.txt.enc.enc -> FILE.txt.enc.enc.enc until the filename is too big. This can be fixed by exiting the loop shorthand or check the file count in the folder and loop that count only.
 ```

## File architecture
```
<<CryptHeader>>
[[ RSA Encrypted
    <<CryptFile>>
    <<CryptFile>>
    <<CryptFile>>
    ...
]]
[[ AES Encrypted
    <<FileData>>
    <<FileData>>
    <<FileData>>
    ...
]]
```

## Used libraries
OpenSSL [https://www.openssl.org/]  
P-Threads [https://man7.org/linux/man-pages/man7/pthreads.7.html]

## Credits
Me, Myself and I
