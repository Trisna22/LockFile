
#include "AESCrypter.h"
#include "RSACrypter.h"

#ifndef Crypter_H
#define Crypter_H

#define READ_SIZE       4096
#define LOG_ALL

class Crypter {
public:
	Crypter();
        ~Crypter();
        bool createCryptFile(string target);
	bool checkCryptFile(string fileName);
private:
        struct CryptFile {
                int fileNameLen;
                char fileName[100];
                bool isFolder;
                unsigned long sizeFileData;
                char fileKey[32];
                char fileIV[16];
        };

        struct CryptHeader {
                unsigned char magic[6];         // Magic bytes.
                unsigned int sizePrivateKey;    // Size of the private key (encrypted).
                char* encryptedPrivateKey;      // The private key.
                char* IvPrivateKey;             // IV for decrypting the private key.
                
                unsigned int countFileInfos;    // Count of file info structures.
        };

        char* encryptedContent;
        bool isFolder;
        CryptHeader cryptHeader;
        CryptHeader generateCryptHeader();

	CryptFile encryptFile(string fileName);
	CryptFile decryptFile(string fileName);

        bool encryptFolder(string fileName);
        bool decryptFolder(string fileName);

        bool copyFileDataToFilePointer(string fileName, FILE* outputFile);
};

#endif // !Crypter_H

Crypter::Crypter()
{

}

Crypter::~Crypter()
{

}

bool Crypter::createCryptFile(string target)
{
        // Check if target is even a folder or file.
        struct stat s;
        if (stat(target.c_str(), &s) == -1) {

                printf("[-] Failed to determine if path is file or folder! Error code: %d\n\n", errno);
                return false;
        }

        this->isFolder = s.st_mode & S_IFDIR ? true : false;

        // Generate our crypt file.
        FILE* outputFile = fopen((target + ".crypt").c_str(), "wb");
        if (outputFile == NULL) {

                printf("[-] Failed to create crypt file! Error code: %d\n\n", errno);
                return false;
        }

        this->cryptHeader = this->generateCryptHeader();

        if (this->isFolder)
                return this->encryptFolder(target);
        else {
                CryptFile cryptFile = this->encryptFile(target);
                
                this->cryptHeader.countFileInfos = 1;
                
                // Write the header to the file.
                fwrite(&this->cryptHeader, 1, sizeof(this->cryptHeader), outputFile);
                printf("[*] Written CryptHeader (%d bytes)\n", sizeof(this->cryptHeader));

                // Write the CryptFile info to the file.
                fwrite(&cryptFile, 1, sizeof(cryptFile), outputFile);
                printf("[*] Written single CryptFile (%d bytes)\n", sizeof(cryptFile));

                // Write the encrypted data to the file.
                // The data is stored in the path with .enc at the end.
                if (!this->copyFileDataToFilePointer(target + ".enc", outputFile))
                        return false;

                fclose(outputFile);
                printf("[!] Locking finished\n");

                #ifdef LOG_ALL
                printf("\n");
                printf("CryptHeader\n");
                printf("  Magic:            %s\n", cryptHeader.magic);
                printf("  Size priv key:    X\n");
                printf("  Enc. priv key:    X\n");
                printf("  IV priv key:      X\n");
                printf("  Count file infos: %d\n\n", cryptHeader.countFileInfos);

                printf("CryptFile\n");
                printf("  Filename length:  %d\n", cryptFile.fileNameLen);
                printf("  Filename:         %s\n", cryptFile.fileName);
                printf("  isFolder:         %s\n", cryptFile.isFolder ? "True" : "False");
                printf("  Content length:   %ld\n", cryptFile.sizeFileData);
                printf("  File key (hex):   %s\n", Utils::convertToHex(cryptFile.fileKey, 32).c_str());
                printf("  File IV (hex):    %s\n", Utils::convertToHex(cryptFile.fileIV, 16).c_str());
                #endif
        }

        // First generate RSA key for all our files.
        // Encrypt the RSA key with our password.
        // Encrypt all files with our RSA key.
        // Save encrypted RSA key and files in single file
        // with headers like magic bytes, file size, 
}

bool Crypter::checkCryptFile(string fileName)
{
        // Check magic bytes.
        return false;
}

/////////// private member functions ///////////////

Crypter::CryptHeader Crypter::generateCryptHeader()
{
        // Magic bytes.
        CryptHeader cryptHeader;
        memset(&cryptHeader, 0, sizeof(cryptHeader)); // Zero out the structure.

        cryptHeader.magic[0] = '.';
        cryptHeader.magic[1] = 'c';
        cryptHeader.magic[2] = 'r';
        cryptHeader.magic[3] = 'y';
        cryptHeader.magic[4] = 'p';
        cryptHeader.magic[5] = 't';

        // If content is a folder.
        //cryptFile.isFolder = this->isFolder;

        return cryptHeader;
        /*
        unsigned int sizePrivateKey;
        char* encryptedPrivateKey;
        unsigned int sizeIv;
        char* iv;
        unsigned long sizeFileData;
        char* fileData;*/
}

Crypter::CryptFile Crypter::encryptFile(string fileName)
{
        CryptFile cryptFile;
        memset(&cryptFile, 0, sizeof(CryptFile));

        FILE *inputFile = fopen(fileName.c_str(), "rb");
        if (inputFile == NULL) {

                printf("[-] Failed to open the file %s! Error code: %d\n\n", fileName.c_str(), errno);
                return cryptFile;
        }

        FILE* outputFile = fopen((fileName + ".enc").c_str(), "wb");
        if (outputFile == NULL) {

                printf("[-] Failed to open the output file for %s\n Error code: %d\n\n", fileName.c_str(), errno);
                return cryptFile;
        }

        // Generate key and set the key.
        AESCrypter aesCrypter;
        aesCrypter.createRandomKey(cryptFile.fileKey);
        if (!aesCrypter.setKey(cryptFile.fileKey, 32)) {

                printf("[-] Failed to set the generated key as encryption key!\n\n");
                return cryptFile;
        }

        // Set the generated IV.
        aesCrypter.setIv(cryptFile.fileIV);

        // Let AES do the work with file.
        unsigned long outputSize;
        if (!aesCrypter.encryptFile(inputFile, outputFile, &outputSize)) {

                printf("[-] Failed to encrypt the file with AES!\n\n");
                return cryptFile;
        }

        // Create a CryptFile object to store the data in the header.
        cryptFile.isFolder = false;
        cryptFile.fileNameLen = fileName.length() +1;   // Length file name.
        Utils::fillCharArray(fileName, (char*)cryptFile.fileName); // The filename.
        cryptFile.sizeFileData = outputSize; // File data size.

        return cryptFile;
}

Crypter::CryptFile Crypter::decryptFile(string fileName)
{
        CryptFile cryptFile;
        return cryptFile;
}

bool Crypter::encryptFolder(string fileName)
{
        return false;
}      

bool Crypter::decryptFolder(string fileName)
{
        return false;
}

bool Crypter::copyFileDataToFilePointer(string fileName, FILE* outputFile)
{
        // Open the encrypted file.
        FILE* inputFile = fopen(fileName.c_str(), "rb");
        if (inputFile == NULL) {

                printf("[-] Failed to open the encrypted file %s! Error code: %d\n\n", errno);
                return false;
        }

        // Read the content of encrypted file and write
        // into the output file.
        char* buffer = (char*)malloc(READ_SIZE);
        int totalBytes = 0;
        for (;;) {

                int readSize = fread(buffer, 1, READ_SIZE, inputFile);
                if (readSize <= 0 && errno != 0) {

                        printf("[-] Failed to read buffer from input file! Error code: %d\n\n", errno);
                        return false;
                }
                else if (readSize <= 0 && errno == 0)
                        break;

                // Write to output file.
                if (fwrite(buffer, 1, readSize, outputFile) <= 0) {
                        printf("[-] Failed to write the buffer into the output file! Error code: %d\n\n", errno);
                        return false;
                }

                totalBytes += readSize;
        }

        // Delete the encrypted file. 
        fclose(inputFile);
        free(buffer);
        printf("[*] Encrypted file data copy success (%d bytes)\n", totalBytes);
        return true;
}