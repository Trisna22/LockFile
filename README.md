# LockFile

Encrypts/decrypts files on local computer with custom combination of encryption methods.  

## TODO
```
- File shredder for the .enc files.
- Section encryption/decryption.
- Create a TUI (Terminal User Interface) animation?
```

## Bugs
 ``` 
- When you' re encrypting in one folder, it loops trough the .enc files too, so
 it will generate FILE.txt.enc -> FILE.txt.enc.enc -> FILE.txt.enc.enc.enc until the filename is too big. This can be fixed by exiting the loop shorthand or check the file count in the folder and loop that count only.
 ```