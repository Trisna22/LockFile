# LockFile

Encrypts/decrypts files on local computer with custom combination of encryption methods.  

## TODO
```
- [ ] Section encryption/decryption.
- [ ] Create a TUI (Terminal User Interface) animation?
- [ ] Threads for better performance
- [~] Use sendfile() function for better performance?
- [ ] RSA stream encrypt instead of blocks of data
- [X] File shredder for the .enc files.
```

## Bugs
 ``` 
- When you' re encrypting in one folder, it loops trough the .enc files too, so
 it will generate FILE.txt.enc -> FILE.txt.enc.enc -> FILE.txt.enc.enc.enc until the filename is too big. This can be fixed by exiting the loop shorthand or check the file count in the folder and loop that count only.
 ```

## New architeture
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