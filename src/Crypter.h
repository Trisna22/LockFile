
#include "AESCrypter.h"
#include "RSACrypter.h"

#ifndef Crypter_H
#define Crypter_H

#define READ_SIZE       4096
#define LOG_ALL
#define SINGLE_FILE     0x01
#define TEMP_FILE       ".crypt_tmp"

class Crypter {
public:
	Crypter();
        ~Crypter();
        bool createCryptFile(string target);
        bool openCryptFile(string target);
        bool readCryptHeader(string target);
        bool readCryptFiles(string target);
	bool checkCryptFile(string fileName);
private:
        struct CryptFile {
                int fileNameLen;                // The size of the filename.
                char fileName[100];             // The filename.
                bool isFolder;                  // Is folder?
                unsigned long sizeFileData;     // File data size.
                char fileKey[32];               // The key of the AES encryption.
                unsigned char fileIV[16];       // The IV of the AES encryption.
                char fileHash[16];              // The hash of the (unencrypted) content.
        };

        struct CryptHeader {
                unsigned char magic[6];         // Magic bytes.
                unsigned int sizePrivateKey;    // Size of the private key (encrypted).
                char* encryptedPrivateKey;      // The private key.
                char* IvPrivateKey;             // IV for decrypting the private key.
                
                unsigned int countFileInfos;    // Count of file info structures. (CryptFiles)
        };
        AESCrypter aesCrypter;
        RSACrypter rsaCrypter;

        char* encryptedContent;
        bool isFolder;
        CryptHeader cryptHeader;
        const EVP_MD *HASH_TYPE = EVP_md5();
        CryptHeader generateCryptHeader();
        bool md5SumFile(string fileName, char* fileHash);

        char* encryptFileInfoSection(string password);
        char* decryptFileInfoSection(string password);

	CryptFile encryptFile(string fileName);
	bool decryptFile(CryptFile fileInfo, FILE* inputFile);

        bool encryptFolder(string fileName);
        bool decryptFolder(string fileName);

        bool copyFileDataToFilePointer(string fileName, FILE* outputFile);
        bool copyFileBufferToFilePointer(FILE* inputFile, unsigned long fileSize, FILE* outputFile);
};

#endif // !Crypter_H

Crypter::Crypter()
{

}

Crypter::~Crypter()
{

}

/**
 * Encrypts new files and stores information about them in a .crypt file.
 * 
 * @param target The target file/folder to encrypt.
 */
bool Crypter::createCryptFile(string target)
{
        // Check if target is even a folder or file.
        struct stat s;
        if (stat(target.c_str(), &s) == -1) {

                if (errno == 2) {
                        printf("[!] The given path doesn't contain a file or folder!\n\n");
                        return false;
                }

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
                if (cryptFile.sizeFileData == 0) return false;
                
                this->cryptHeader.countFileInfos = SINGLE_FILE;
                
                // Write the header to the file.
                fwrite(&this->cryptHeader, 1, sizeof(this->cryptHeader), outputFile);
                printf("[*] Written CryptHeader (%d bytes)\n", sizeof(this->cryptHeader));

                // Encrypt the file info section. (CryptFile)
                // this->encryptFileInfoSection(password)

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
                printf("  Enc. data size:   %ld\n", cryptFile.sizeFileData);
                printf("  File key (hex):   %s\n", Utils::convertToHex(cryptFile.fileKey, 32).c_str());
                printf("  File IV (hex):    %s\n", Utils::convertToHex((char*)cryptFile.fileIV, 16).c_str());
                printf("  File hash (MD5):  %s\n\n", Utils::convertToHex(cryptFile.fileHash, 16).c_str());
                #endif
        }

        // First generate RSA key for all our files.
        // Encrypt the RSA key with our password.
        // Encrypt all files with our RSA key.
        // Save encrypted RSA key and files in single file
        // with headers like magic bytes, file size, 
}

/**
 * Decrypts the .crypt file to the original files.
 * 
 * @param target The .crypt file with the original files
 */
bool Crypter::openCryptFile(string target)
{
        if (!this->checkCryptFile(target)) {
                return false;
        }

        FILE* inputFile = fopen(target.c_str(), "rb");
        if (inputFile == NULL) {
                printf("[-] Failed to open the crypt file! Error code: %d\n\n", errno);
                return false;
        }

        CryptHeader cryptHeader;
        int fileRead = fread(&cryptHeader, 1, sizeof(CryptHeader), inputFile);
        if (fileRead == -1) {

                printf("[-] Failed to read the crypt file! Error code: %d\n\n", errno);
                return false;
        }
        else if (fileRead == 0) {

                printf("[-] Invalid crypt file, file is empty!\n\n");
                return false;
        }

        // Decrypt the file info section.
        // this->decryptFileInfoSection(password)

        // Save every file info object in a array.
        CryptFile fileInfos[cryptHeader.countFileInfos];
        for (int i = 0; i < cryptHeader.countFileInfos; i++) {

                // Decrypt every file/folder in this file.
                CryptFile cryptFile;
                fileRead = fread(&cryptFile, 1, sizeof(CryptFile), inputFile);
                if (fileRead == -1) {

                        printf("[-] Failed to read the buffer for CryptFile[%d]! Error code: %d\n\n", i, errno);
                        return false;
                }
                else if (fileRead == 0) {
                        
                        printf("[-] Structure empty! Invalid count of file infos!\n\n");
                        return false;
                }

                // Put the results in a list.
                fileInfos[i] = cryptFile;
        }

        // Loop trough the file infos.
        for (int i = 0; i < cryptHeader.countFileInfos; i++) {
                
                if (fileInfos[i].isFolder) {
                        // DO something.
                }

                if (!this->decryptFile(fileInfos[i], inputFile)) {

                        printf("Failed to decrypt file number %d with filename %s!\n\n", i, fileInfos[i].fileName);
                        return false;
                }

                printf("[!] Unpacked and decrypted %s\n", fileInfos[i].fileName);
        }

        fclose(inputFile);
        return true;
}

/**
 * Reads the CryptHeader object from the .crypt file and displays it.
 * 
 * @param target The .crypt file to read from.
 */
bool Crypter::readCryptHeader(string target)
{
        if (!this->checkCryptFile(target))
                return false;

        FILE* inputFile = fopen(target.c_str(), "rb");
        if (inputFile == NULL) {

                printf("[-] Failed to open the crypt file! Error code: %d\n\n", errno);
                return false;
        }

        CryptHeader cryptHeader;
        int fileRead = fread(&cryptHeader, 1, sizeof(CryptHeader), inputFile);
        if (fileRead == -1) {

                printf("[-] Failed to read the crypt file! Error code: %d\n\n", errno);
                return false;
        }
        else if (fileRead == 0) {

                printf("[-] Invalid crypt file, file is empty!\n\n");
                return false;
        }

        fclose(inputFile);

        // Print out the information.
        printf("CryptHeader\n");
        printf("  Magic:            %s\n", cryptHeader.magic);
        printf("  Size priv key:    X\n");
        printf("  Enc. priv key:    X\n");
        printf("  IV priv key:      X\n");
        printf("  Count file infos: %d\n\n", cryptHeader.countFileInfos);
        return true;
}

/**
 * Reads the content of the .crypt file for giving global information.
 * 
 * @param target The given .crypt file to read from.
 */
bool Crypter::readCryptFiles(string target)
{
        if (!this->checkCryptFile(target.c_str()))
                return false;

        FILE* inputFile = fopen(target.c_str(), "rb");
        if (inputFile == NULL) {

                printf("[-] Failed to open the crypt file! Error code: %d\n\n", errno);
                return false;
        }

        CryptHeader cryptHeader;
        int fileRead = fread(&cryptHeader, 1, sizeof(CryptHeader), inputFile);
        if (fileRead == -1) {

                printf("[-] Failed to read the crypt file! Error code: %d\n\n", errno);
                return false;
        }
        else if (fileRead == 0) {

                printf("[-] Invalid crypt file, file is empty!\n\n");
                return false;
        }

        // Decrypt the file info section.
        // this->decryptFileInfoSection(password)

        // Looping trough CryptFiles.
        for (int i = 0; i < cryptHeader.countFileInfos; i++) {

                CryptFile cryptFile;
                fileRead = fread(&cryptFile, 1, sizeof(CryptFile), inputFile);
                if (fileRead == -1) {

                        printf("[-] Failed to read the buffer for CryptFile[%d]! Error code: %d\n\n", i, errno);
                        return false;
                }
                else if (fileRead == 0) {
                        
                        printf("[-] Structure empty! Invalid count of file infos!\n\n");
                        return false;
                }

                // Print out the file info.
                printf("CryptFile [%d]\n", i);
                printf("  Filename length:  %d\n", cryptFile.fileNameLen);
                printf("  Filename:         %s\n", cryptFile.fileName);
                printf("  isFolder:         %s\n", cryptFile.isFolder ? "True" : "False");
                printf("  Enc. data size:   %ld\n", cryptFile.sizeFileData);
                printf("  File key (hex):   %s\n", Utils::convertToHex(cryptFile.fileKey, 32).c_str());
                printf("  File IV (hex):    %s\n", Utils::convertToHex((char*)cryptFile.fileIV, 16).c_str());
                printf("  File hash (MD5):  %s\n\n", Utils::convertToHex(cryptFile.fileHash, 16).c_str());
        }

        fclose(inputFile);
        return true;
}

/**
 * Checks the given .crypt file if it is a valid crypt file.
 * 
 * @param target The given .crypt file to check.
 */
bool Crypter::checkCryptFile(string target)
{
        // Check magic bytes.
        FILE* inputFile = fopen(target.c_str(), "rb");
        if (inputFile == NULL) {

                printf("[-] Failed to open the crypt file! Error code: %d\n\n", errno);
                return false;
        }

        CryptHeader cryptHeader;
        int fileRead = fread(&cryptHeader, 1, sizeof(CryptHeader), inputFile);
        if (fileRead == -1) {

                printf("[-] Failed to read the crypt file! Error code: %d\n\n", errno);
                return false;
        }
        else if (fileRead == 0) {

                printf("[-] Invalid crypt file, file is empty!\n\n");
                return false;
        }

        // Check the magic bytes.
        if (!(cryptHeader.magic[0] == '.' && cryptHeader.magic[1] == 'c' &&
                cryptHeader.magic[2] == 'r' && cryptHeader.magic[3] == 'y' &&
                cryptHeader.magic[4] == 'p' && cryptHeader.magic[5] == 't')) {
                
                printf("[-] Invalid file format! Crypt magic bytes not correct!\n\n");
                return false;
        }

        fclose(inputFile);
        return true;
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

        return cryptHeader;
}

/**
 * Generates the MD5 hash of the content of the given file.
 * 
 * @param fileName The file to get the hash from.
 * @param fileHash The pointer to store the hash in.
 */
bool Crypter::md5SumFile(string fileName, char* fileHash)
{
	EVP_MD_CTX *hashContext = EVP_MD_CTX_create();

	int hashLen = EVP_MD_size(HASH_TYPE);
        unsigned char *hash = (unsigned char *) malloc(hashLen);

	EVP_MD_CTX_init(hashContext);
	EVP_DigestInit_ex(hashContext, HASH_TYPE, NULL);

        FILE* inputFile = fopen(fileName.c_str(), "rb");
        if (inputFile == NULL) {

                printf("[-] Failed to open the file %s for hashing! Error code: %d\n\n", fileName.c_str(), errno);
                return false;
        }

        char* buffer = (char*)malloc(READ_SIZE);
        for (;;) {

                int readSize = fread(buffer, 1, READ_SIZE, inputFile);
                if (readSize <= 0 && errno != 0) {

                        printf("[-] Failed to read the file %s for hashing! Error code: %d\n\n", fileName.c_str(), errno);
                        return false;
                }
                else if (readSize <= 0 && errno == 0)
                        break;
                else if (readSize == 0) {

                        printf("[-] Failed to create a hash for the file %s! File is empty!\n\n", fileName.c_str());
                        return false;
                }

	        EVP_DigestUpdate(hashContext, buffer, readSize);
        }

	EVP_DigestFinal_ex(hashContext, hash, NULL);
        strncpy(fileHash, (char*)hash, 16); // Copy bytes to pointer.
        // Cleanup.
        free(buffer);
        free(hash);
        return true;
}

char* Crypter::encryptFileInfoSection(string password)
{
        return NULL;
}

char* Crypter::decryptFileInfoSection(string password)
{
        return NULL;
}

/**
 * Encrypts the given file and returns the CryptFile object with our file data.
 * 
 * @param fileName The path to the file we want to encrypt.
 */
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

        // Set the content hash of the unencrypted file.
        if (!this->md5SumFile(fileName, cryptFile.fileHash)) {

                printf("[-] Failed to MD5 hash the unencrypted file!\n\n");
                return cryptFile;
        }

        // Generate key and set the key.
        this->aesCrypter.createRandomKey(cryptFile.fileKey);
        if (!this->aesCrypter.setKey(cryptFile.fileKey, 32)) {

                printf("[-] Failed to set the generated key as encryption key!\n\n");
                return cryptFile;
        }

        // Set the generated IV.
        this->aesCrypter.setIv(cryptFile.fileIV);

        // Let AES do the work with file.
        unsigned long outputSize;
        if (!this->aesCrypter.encryptDecryptFile(inputFile, outputFile, &outputSize)) {

                printf("[-] Failed to encrypt the file with AES!\n\n");
                return cryptFile;
        }

        // Create a CryptFile object to store the data in the header.
        string onlyFileName = Utils::validateSingleFile(fileName); // To get only the filename without path.     
        cryptFile.isFolder = false;
        cryptFile.fileNameLen = onlyFileName.length() +1;   // Length file name.
        Utils::fillCharArray(onlyFileName, (char*)cryptFile.fileName); // The filename.
        cryptFile.sizeFileData = outputSize; // File data size.

        return cryptFile;
}

/**
 * Decrypts the section of the .crypt file to the original file.
 * 
 * @param fileInfo The CryptFile object with information about the file.
 * @param inputFile The input .crypt file to read from.
 */
bool Crypter::decryptFile(CryptFile fileInfo, FILE* inputFile)
{
        // Setting up the variables.
        unsigned long fileSize = fileInfo.sizeFileData;
        string fileName = fileInfo.fileName;

        printf("[*] Decrypting file %s\n", fileName.c_str());

        FILE* outputFile = fopen(TEMP_FILE, "wb");
        if (outputFile == NULL) {

                printf("[-] Failed to create a temporary file! Error code: %d\n\n", errno);
                return false;
        }

        if (!this->copyFileBufferToFilePointer(inputFile, fileSize, outputFile)) {

                printf("[-] Failed to copy the bytes to a temporary file!\n\n");
                return false;
        }

        // Decrypt the file to the actual file.
        FILE* encryptedFile = fopen(TEMP_FILE, "rb");
        FILE* outputFile2 = fopen(fileName.c_str(), "wb");

        printf("[*] Setting IV and decryption key\n");

        this->aesCrypter.setIv2(fileInfo.fileIV);

        // Set the key and IV and start decrypting.
        if (!this->aesCrypter.setKey(fileInfo.fileKey, 32, // The key of the file.
                fileInfo.fileIV, // The IV of the file.
                true
        )); 

        unsigned long outputSize;
        if (!this->aesCrypter.encryptDecryptFile(encryptedFile, outputFile2, &outputSize)) {

                printf("[-] Failed to decrypt the file with the key and IV!\n\n");
                return false;
        }

        // Delete the temp file.
        if (unlink(TEMP_FILE) == -1) {

                printf("[-] Failed to delete the temporary file! Error code: %d\n\n", errno);
                return false;
        }

        // Validate the file with the hash.
        char hashCheck[16];
        if (!this->md5SumFile(fileName.c_str(), hashCheck)) {
                
                printf("[-] Failed to retrieve the hash of the file to compare!\n\n");
                return false;
        }

        printf("[+] Decryption and hash comparising completed!\n");

        if (Utils::convertToHex(hashCheck, 16) != Utils::convertToHex(fileInfo.fileHash, 16)) {
                
                printf("[!] Invalid hash, crypt file has been altered without our permission!\n\n");
                printf("%s != %s\n", Utils::convertToHex(hashCheck, 16).c_str(), Utils::convertToHex(fileInfo.fileHash, 16).c_str());
                return false;
        }
        return true;
}

bool Crypter::encryptFolder(string fileName)
{
        return false;
}      

bool Crypter::decryptFolder(string fileName)
{
        return false;
}

/**
 * Writes the content of the target filename to the given output file pointer.
 * 
 * @param fileName The target file fileName.
 * @param outputFile The pointer to the file descriptor.
 */
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
        printf("[*] Encrypted file data copy (%d bytes)\n", totalBytes);
        return true;
}

/**
 * Copies the partial content of the input file to the output file.
 * 
 * @param inputFile The input file pointer to read the buffer from.
 * @param fileSize  The size of the buffer to read.
 * @param outputFile The pointer to the output file.
 */
bool Crypter::copyFileBufferToFilePointer(FILE* inputFile, unsigned long fileSize, FILE* outputFile)
{
        char* buffer = (char*)malloc(READ_SIZE);

        for (;;) {
                // Write data to output.
                int readSize = fread(buffer, 1, READ_SIZE, inputFile);
                if (readSize <= 0 && errno != 0) {

                        printf("[-] Failed to read buffer from input file! Error code: %d\n\n", errno);
                        return false;
                }
                else if (readSize <= 0 && errno == 0)
                        break;

                if (fwrite(buffer, 1, readSize, outputFile) <= 0) {

                        printf("[-] Failed to write the input data to the output file! Error code: %d\n\n", errno);
                        return false;
                }
        }

        // Cleanup, WARNING: Do not close the inputFile, we still need it.
        free(buffer);
        fclose(outputFile);
        return true;
}
