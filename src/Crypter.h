
#include "AESCrypter.h"
#include "RSACrypter.h"

#ifndef Crypter_H
#define Crypter_H

#define READ_SIZE       4096
#define DONT_LOG_ALL
#define SINGLE_FILE     0x01
#define TEMP_FILE       ".crypt_tmp"
#define CRYPT_EXTENSION ".crypt"

#define FILL_IV         "XXXXXXXXXXXXXXXX"
#define FILL_KEY        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

class Crypter {
public:
	Crypter();
        ~Crypter();
        bool createCryptFile(string target, char* password);
        bool openCryptFile(string target, char* password);

        bool readCryptHeader(string target);
        bool readCryptFiles(string target);
	bool checkCryptFile(string fileName);
private:
        /**
         * @brief 
         * Change the CryptFile structure to change fileName to be unlimited size, bc this 
         * triggers a stack overflow and corrupts our memory. We can keep track of the length
         *  with fileNameLen.
         * 
         * DONE
         */
        struct __attribute__ ((packed)) CryptFile {
                int fileNameLen;                // The size of the filename.
                bool isFolder;                  // Is folder?
                unsigned long sizeFileData;     // File data size.
                unsigned char fileKey[32];      // The key of the AES encryption.
                unsigned char fileIV[16];       // The IV of the AES encryption.
                unsigned char fileHash[16];     // The hash of the (unencrypted) content.
                char *fileName;                 // The filename.
        };

        struct __attribute__ ((packed)) CryptFileRead {
                int fileNameLen;                // The size of the filename.
                bool isFolder;                  // Is folder?
                unsigned long sizeFileData;     // File data size.
                unsigned char fileKey[32];      // The key of the AES encryption.
                unsigned char fileIV[16];       // The IV of the AES encryption.
                unsigned char fileHash[16];     // The hash of the (unencrypted) content.
                //char fileName[fileNameLen];   // The filename (not in structure, but after)
        };
        
        struct __attribute__ ((packed)) CryptHeader {
                unsigned char magic[6];         // Magic bytes.
                
                unsigned int countFileInfos;    // Count of file info structures. (CryptFiles)
                unsigned long sizeCryptFiles;   // The size of the encrypted CryptFile section headers.
                unsigned int sizePrivateKey;    // The size of the private key.
                // unsigned char* encryptedPrivateKey;// The RSA private key.
        };

        struct __attribute__ ((packed)) CryptHeaderRead {
                unsigned char magic[6];         // Magic bytes.
                
                unsigned int countFileInfos;    // Count of file info structures. (CryptFiles)
                unsigned long sizeCryptFiles;   // The size of the encrypted CryptFile section headers.
                unsigned int sizePrivateKey;    // The size of the private key.
                // unsigned char* encryptedPrivateKey;// The RSA private key.
        };

        AESCrypter aesCrypter;
        RSACrypter rsaCrypter;

        EVP_MD_CTX *hashContext;
        const EVP_MD *HASH_TYPE = EVP_md5();
        bool md5SumFile(string fileName, unsigned char* fileHash);

        CryptHeader generateCryptHeader();
        CryptFile generateCryptFolder(string folderName);
        bool writeFileToCryptFile(string fileName, FILE* outputFile);

        // Info section encryption/decryption.0:16 / 3:01
        char* encryptFileInfoSection(string password, string fileName, unsigned long sizeCryptFiles);
        char* decryptFileInfoSection(string password, string fileName);

        // File encryption/decryption.
	CryptFile encryptFile(string fileName, bool fromFolder = false);
	bool decryptFile(CryptFileRead fileInfo, string fileName, FILE* inputFile);

        // Folder encryption/decryption.
        bool encryptFolder(string fileName, string password, FILE* outputFile);
        bool decryptFolder(CryptFileRead fileInfo, string folderName);
        vector<CryptFile> loopFolder(string fileName);

        bool copyFileDataToFilePointer(string fileName, FILE* outputFile);
        bool copyFileBufferToFilePointer(FILE* inputFile, unsigned long fileSize, FILE* outputFile);
};

#endif // !Crypter_H
 
Crypter::Crypter()
{
        hashContext = EVP_MD_CTX_create();
	EVP_MD_CTX_init(hashContext);
	EVP_DigestInit_ex(hashContext, HASH_TYPE, NULL);
}       

Crypter::~Crypter()
{

}

/**
 * Encrypts new files and stores information about them in a .crypt file.
 * 
 * @param target The target file/folder to encrypt.
 */
bool Crypter::createCryptFile(string target, char* password)
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

        bool isFolder = s.st_mode & S_IFDIR ? true : false;


        // Generate our crypt file.
        FILE* outputFile = fopen((target + CRYPT_EXTENSION).c_str(), "wb");
        if (outputFile == NULL) {

                printf("[-] Failed to create crypt file! Error code: %d\n\n", errno);
                return false;
        }

        // Generate our RSA keys.
        if (!rsaCrypter.generateKeys(password)) {

                printf("[-] Failed to generate the public/private keys!\n\n");
                return false;
        }
 
        if (isFolder) {

                if (!this->encryptFolder(target, password, outputFile))
                        return false;
        }
        else 
                if (!this->writeFileToCryptFile(target, outputFile))
                        return false;

        return true;
}

/**
 * Decrypts the .crypt file to the original files.
 * 
 * @param target The .crypt file with the original files
 */
bool Crypter::openCryptFile(string target, char* password)
{
        if (!this->checkCryptFile(target)) {
                return false;
        }


        FILE* inputFile = fopen(target.c_str(), "rb");
        if (inputFile == NULL) {
                printf("[-] Failed to open the crypt file! Error code: %d\n\n", errno);
                return false;
        }

        printf("[*] Reading CryptHeader (%d bytes)\n", sizeof(CryptHeader));
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

        // Decrypt the section with CryptFile objects.
        if (!this->decryptFileInfoSection(password, target))
                 return false;
                
        // Save every file info object in a array.
        printf("[*] About to read %d CryptFile objects\n", cryptHeader.countFileInfos);

        vector<CryptFileRead> cryptFiles;
        vector<string> fileNames;
        for (int i = 0; i < cryptHeader.countFileInfos; i++) {

                // Decrypt every file/folder in this file.
                CryptFileRead cryptFile;
                fileRead = fread(&cryptFile, 1, sizeof(CryptFile), inputFile);
                if (fileRead == -1) {

                        printf("[-] Failed to read the buffer for CryptFile[%d]! Error code: %d\n\n", i, errno);
                        return false;
                }
                else if (fileRead == 0) {
                        
                        printf("[-] Structure empty! Invalid count of file infos!\n\n");
                        return false;
                }
                
                char fileNameBuffer[cryptFile.fileNameLen];
                fread(&fileNameBuffer, 1, cryptFile.fileNameLen, inputFile);
                fileNameBuffer[cryptFile.fileNameLen] = '\0';
                
                fileNames.push_back(fileNameBuffer);
                cryptFiles.push_back(cryptFile);
        }

        printf("[*] Decrypting file data and writing to drive\n");
        bool progressBar = cryptHeader.countFileInfos > 10;
        float progress = 0.0;

        for (int i = 0; i < cryptFiles.size(); i++) {

                CryptFileRead cryptFile = cryptFiles.at(i);
                string fileName = fileNames.at(i);

                if (progressBar) {
                        Utils::printProgressBar(progress);
                }

                if (cryptFile.isFolder) {

                        if (!progressBar)
                                printf("[*] Decrypting folder %s\n", fileName.c_str());
                        this->decryptFolder(cryptFile, fileName);
                        continue;
                }

                if (!progressBar)
                        printf("[*] Decrypting file %s\n", fileName.c_str());

                if (!this->decryptFile(cryptFile, fileName, inputFile)) {

                        printf("Failed to decrypt file number %d with filename %s!\n\n", i, fileName.c_str());
                        return false;
                }

                if (!progressBar)
                        printf("[!] Unpacked and decrypted %s\n", fileName.c_str());

                // Increment in progress.
                progress = ((float)i / (float)cryptHeader.countFileInfos);
        }

        if (progressBar)
                Utils::printProgressBar(1);

        printf("\n[!] Decrypting and unpacking finished\n\n");

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

        CryptHeaderRead cryptHeader;
        printf("Size of Header: %ld\n", sizeof(CryptHeaderRead));
        int fileRead = fread(&cryptHeader, 1, sizeof(CryptHeaderRead), inputFile);
        if (fileRead == -1) {

                printf("[-] Failed to read the crypt file! Error code: %d\n\n", errno);
                return false;
        }
        else if (fileRead == 0) {

                printf("[-] Invalid crypt file, file is empty!\n\n");
                return false;
        }
        
        unsigned char privateKey[cryptHeader.sizePrivateKey];
        fileRead = fread(&privateKey, 1, cryptHeader.sizePrivateKey, inputFile);
        if (fileRead == -1) {
                printf("[-] Failed to read the crypt file! Error code: %d\n\n", errno);
                return false;
        }
        else if (fileRead == 0) {

                printf("[-] Invalid crypt file, file is empty!\n\n");
                return false;
        }
        privateKey[fileRead] ='\0'; // String termination.

        fclose(inputFile);

        // Print out the information.
        printf("CryptHeader\n");
        printf("  Magic:                        %s\n", cryptHeader.magic);
        printf("  Size priv key:                %ld\n", cryptHeader.sizeCryptFiles);
        printf("  Count file CryptFile objects: %d\n", cryptHeader.countFileInfos);
        printf("  Encrypted private key:        \n\n%s\n", privateKey);
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

        CryptHeaderRead cryptHeader;
        int fileRead = fread(&cryptHeader, 1, sizeof(CryptHeaderRead), inputFile);
        if (fileRead == -1) {

                printf("[-] Failed to read the crypt file! Error code: %d\n\n", errno);
                return false;
        }
        else if (fileRead == 0) {

                printf("[-] Invalid crypt file, file is empty!\n\n");
                return false;
        }

        char privateKey[cryptHeader.sizePrivateKey];
        fread(&privateKey, 1, cryptHeader.sizePrivateKey + 1, inputFile);
        privateKey[cryptHeader.sizePrivateKey] = '\0';

        // Decrypt the file info section.
        // this->decryptFileInfoSection(password)

        // Looping trough CryptFiles.
        for (int i = 0; i < cryptHeader.countFileInfos; i++) {

                CryptFileRead cryptFile;
                fileRead = fread(&cryptFile, 1, sizeof(CryptFileRead), inputFile);
                if (fileRead == -1) {

                        printf("[-] Failed to read the buffer for CryptFile[%d]! Error code: %d\n\n", i, errno);
                        return false;
                }
                else if (fileRead == 0) {
                        
                        printf("[-] Structure empty! Invalid count of file infos!\n\n");
                        return false;
                }

                char fileNameBuffer[cryptFile.fileNameLen];
                fread(&fileNameBuffer, 1, cryptFile.fileNameLen, inputFile);
                fileNameBuffer[cryptFile.fileNameLen] = '\0';

                // Print out the file info.
                printf("CryptFile [%d]\n", i);
                printf("  Filename length:  %d\n", cryptFile.fileNameLen);
                printf("  Filename:         %s\n", fileNameBuffer);
                printf("  isFolder:         %s\n", cryptFile.isFolder ? "True" : "False");
                printf("  Enc. data size:   %ld\n", cryptFile.sizeFileData);
                printf("  File key (hex):   %s\n", Utils::convertToHex(cryptFile.fileKey, 32).c_str());
                printf("  File IV (hex):    %s\n", Utils::convertToHex(cryptFile.fileIV, 16).c_str());
                printf("  File hash (MD5):  %s\n\n", Utils::convertToHex(cryptFile.fileHash, 16).c_str());

                // // Skip over the file. (That is our encrypted content)
                // char bufferData[cryptFile.sizeFileData];
                // fread(bufferData, 1, cryptFile.sizeFileData, inputFile);
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

/**
 * Generates the CryptHeader structure for the CryptFile. 
 * 
 * @return Crypter::CryptHeader 
 **/
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
Crypter::CryptFile Crypter::generateCryptFolder(string folderName)
{
        CryptFile cryptFile;
        cryptFile.isFolder = true;

        memset(cryptFile.fileIV, 0, AES_BLOCK_SIZE);
        memset(cryptFile.fileKey, 0, AES_256_KEY_SIZE);
        memset(cryptFile.fileHash, 0, AES_BLOCK_SIZE);
        cryptFile.fileName = new char[folderName.length() +1];
        strncpy(cryptFile.fileName, folderName.c_str(), folderName.length() +1);

        cryptFile.fileNameLen = folderName.length() + 1;
        cryptFile.sizeFileData = 0;
        return cryptFile;
}

/**
 * Writes the single given file to the .crypt file and encrypts the payload.
 * 
 * @param fileName  The filename to the target file.
 * @param outputFile The output file pointer to write the data in.
 **/
bool Crypter::writeFileToCryptFile(string fileName, FILE* outputFile) {
                
        CryptFile cryptFile = this->encryptFile(fileName);
        if (cryptFile.sizeFileData == 0) return false;
        
        CryptHeader cryptHeader = this->generateCryptHeader();
        cryptHeader.countFileInfos = SINGLE_FILE;
        cryptHeader.sizeCryptFiles = sizeof(cryptFile); // The size to decrypt.
        
        // Write the encrypted private key to the header. 
        int sizePrivateKey;
        char* privateKey = rsaCrypter.getPrivateKey(&sizePrivateKey);
        privateKey[sizePrivateKey] = '\0';
        fwrite(privateKey, 1, sizePrivateKey, outputFile);

        
        // Write the header to the file.
        fwrite(&cryptHeader, 1, sizeof(cryptHeader), outputFile);
        printf("[*] Written CryptHeader (%d bytes)\n", sizeof(cryptHeader));

        // Write the CryptFile info to the file.
        fwrite(&cryptFile, 1, sizeof(cryptFile), outputFile);
        printf("[*] Written single CryptFile (%d bytes)\n", sizeof(cryptFile));

        // Write the encrypted data to the file.
        // The data is stored in the path with .enc at the end.
        if (!this->copyFileDataToFilePointer(fileName + ".enc", outputFile))
                return false;

        // Delete our file with our shredder.
        if (!Utils::shredFile(fileName + ".enc")) {
                printf("\n[!] Failed to shred our temporary files!\n");
        }

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
        printf("  File IV (hex):    %s\n", Utils::convertToHex(cryptFile.fileIV, 16).c_str());
        printf("  File hash (MD5):  %s\n\n", Utils::convertToHex(cryptFile.fileHash, 16).c_str());
        #endif
        return true;
}

/**
 * Generates the MD5 hash of the content of the given file.
 * 
 * @param fileName The file to get the hash from.
 * @param fileHash The pointer to store the hash in.
 */
bool Crypter::md5SumFile(string fileName, unsigned char* fileHash)
{
	int hashLen = EVP_MD_size(HASH_TYPE);
        // unsigned char *hash = (unsigned char *) malloc(hashLen);
        unsigned char* hash = new unsigned char[hashLen];


        FILE* inputFile = fopen(fileName.c_str(), "rb");
        if (inputFile == NULL) {

                printf("[-] Failed to open the file %s for hashing! Error code: %d\n\n", fileName.c_str(), errno);
                return false;
        }

        char* buffer = new char[READ_SIZE];
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
        strncpy(reinterpret_cast<char*>(fileHash), reinterpret_cast<char*>(hash), 16); // Copy bytes to pointer.
        
        // Cleanup.
        free(buffer);
        free(hash);
        fclose(inputFile);
        return true;
}

char* Crypter::encryptFileInfoSection(string password, string fileName, unsigned long sizeCryptFiles)
{
        FILE* writePointer = fopen(fileName.c_str(), "wb+");
        if (writePointer == NULL) {
                printf("# Failed to open file to encrypt section headers! Error code: %d\n\n", errno);
                return NULL;
        }

        // Skip the bytes over the magic header.
        fseek(writePointer, sizeof(CryptHeader), SEEK_SET);
        printf("Location of write pointer for section header ecnrypt: %ld\n", ftell(writePointer));

        // rsaCrypter.encryptData();
        return NULL;
}

char* Crypter::decryptFileInfoSection(string password, string fileName)
{
        printf("Function to decrypt doesn't exists yet!\n");
        return NULL;
}

/**
 * Encrypts the given file and returns the CryptFile object with our file data.
 * 
 * @param fileName The path to the file we want to encrypt.
 */
Crypter::CryptFile Crypter::encryptFile(string fileName, bool fromFolder)
{
        CryptFile cryptFile;

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
        cryptFile.fileKey[AES_256_KEY_SIZE] = '\0'; // For string termination.
        if (!this->aesCrypter.setKey(cryptFile.fileKey, AES_256_KEY_SIZE)) {

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
        // First check if file is part of folder structure.
        if (!fromFolder) {
                string onlyFileName = Utils::validateSingleFile(fileName); // To get only the filename without path.     
                cryptFile.fileNameLen = onlyFileName.length() +1;   // Length file name.
                cryptFile.fileName = new char[cryptFile.fileNameLen];
                memcpy(cryptFile.fileName, fileName.c_str(), cryptFile.fileNameLen);
        }
        else {
                cryptFile.fileNameLen = fileName.length() +1;   // Length file name.
                cryptFile.fileName = new char[cryptFile.fileNameLen];
                memcpy(cryptFile.fileName, fileName.c_str(), cryptFile.fileNameLen);
        }

        cryptFile.isFolder = false;
        cryptFile.sizeFileData = outputSize; // File data size.

        return cryptFile;
}

/**
 * Decrypts the section of the .crypt file to the original file.
 * 
 * @param fileInfo The CryptFile object with information about the file.
 * @param inputFile The input .crypt file to read from.
**/
bool Crypter::decryptFile(CryptFileRead fileInfo, string fileName, FILE* inputFile)
{
        // Setting up the variables.
        unsigned long fileSize = fileInfo.sizeFileData;

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

        if (encryptedFile == NULL || outputFile2 == NULL) {
                printf("[-] Failed to open the input/output files! Error code: %d\n", errno);
                return false;
        }

        this->aesCrypter.setIv2(fileInfo.fileIV);

        // printf("CryptFile\n");
        // printf("  Filename:         %s\n", fileInfo.fileName);
        // printf("  isFolder:         %s\n", fileInfo.isFolder ? "True" : "False");
        // printf("  Enc. data size:   %ld\n", fileInfo.sizeFileData);
        // printf("  File key (hex):   %s\n", Utils::convertToHex(fileInfo.fileKey, 32).c_str());
        // printf("  File IV (hex):    %s\n", Utils::convertToHex(fileInfo.fileIV, 16).c_str());
        // printf("  File hash (MD5):  %s\n\n", Utils::convertToHex(fileInfo.fileHash, 16).c_str());

        // Set the key and IV and start decrypting.
        fileInfo.fileKey[AES_256_KEY_SIZE] = '\0'; // For string termination.
        if (!this->aesCrypter.setKey(fileInfo.fileKey, AES_256_KEY_SIZE, // The key of the file.
                fileInfo.fileIV, // The IV of the file.
                true
        )); 

        unsigned long outputSize;
        if (!this->aesCrypter.encryptDecryptFile(encryptedFile, outputFile2, &outputSize)) {

                printf("[-] Failed to decrypt the file with the key and IV!\n\n");
                return false;
        }

        // Delete the temp file.
        if (!Utils::shredFile(TEMP_FILE)) {

                printf("[-] Failed to delete the temporary file! Error code: %d\n\n", errno);
                return false;
        }

        // Validate the file with the hash.
        unsigned char hashCheck[16];
        if (!this->md5SumFile(fileName.c_str(), hashCheck)) {
                
                printf("[-] Failed to retrieve the hash of the file to compare!\n\n");
                return false;
        }


        if (Utils::convertToHex(hashCheck, 16) != Utils::convertToHex(fileInfo.fileHash, 16)) {
                
                printf("[!] Invalid hash, crypt file has been altered and is now corrupted!\n\n");
                printf("%s != %s\n", Utils::convertToHex(hashCheck, 16).c_str(), Utils::convertToHex(fileInfo.fileHash, 16).c_str());
                return false;
        }

        return true;
}

/**
 * Encrypts a folder structure.
 * 
 * @param folderName The folder path to encrypt into a CryptFile.
 */
bool Crypter::encryptFolder(string folderName, string password, FILE* outputFile)
{
        printf("[*] Scanning %s and encrypting data...\n", folderName.c_str());
        vector<CryptFile> folderList = this->loopFolder(folderName);

        // Generate the crypt header structure.
        CryptHeader cryptHeader = this->generateCryptHeader();
        cryptHeader.countFileInfos = folderList.size();

        // Write the encrypted private key to the header. 
        int sizePrivateKey;
        char* privateKey = rsaCrypter.getPrivateKey(&sizePrivateKey);
        privateKey[sizePrivateKey] = '\0';
        cryptHeader.sizePrivateKey = sizePrivateKey;

        // Calculate the size of all CryptFiles.
        unsigned long sizeCryptFiles = 0;
        for (int i = 0; i < folderList.size(); i++) {
                sizeCryptFiles += folderList.at(i).fileNameLen + sizeof(folderList.at(i));
        }
        cryptHeader.sizeCryptFiles = sizeCryptFiles;
        
        // Write the header to the file.
        fwrite(&cryptHeader, 1, sizeof(cryptHeader), outputFile);
        printf("[*] Written CryptHeader (%d bytes)\n", sizeof(cryptHeader));
        fwrite(privateKey, 1, sizePrivateKey, outputFile);
        printf("[*] Written encrypted private key (%d bytes)\n", sizePrivateKey);

        // Write all the crypt file objects.
        printf("[*] About to write %d CryptFile objects\n", folderList.size());
        printf("[*] Generating keys and encrypting file data\n");

        bool progressBar = folderList.size() > 10;
        for (int i = 0; i < folderList.size(); i++) {

                CryptFile cryptFile = folderList.at(i);
                fwrite(&cryptFile, 1, sizeof(cryptFile), outputFile);

                if (!progressBar)
                        printf("[*] Written cryptfile %s (%d bytes)\n", cryptFile.fileName, sizeof(cryptFile));

                // Write the filename seperately.
                fwrite(cryptFile.fileName, 1, cryptFile.fileNameLen, outputFile);
        }

        printf("[*] Writing encrypted file data to the end of the CryptFile!\n");
        // Progress bar. (if possible)
        float progress = 0.0;

        // Write the encrypted file data at the end.
        for (int i = 0; i < folderList.size(); i++) {

                CryptFile cryptFile = folderList.at(i);

                // Increment in progress.
                progress = ((float)i / (float)folderList.size());

                // If it is a folder, we don't have to copy anything.
                if (cryptFile.isFolder)
                        continue;

                if (progressBar) {
                        Utils::printProgressBar(progress);
                }
                else
                        printf("[*] Written encrypted data %s (%d bytes)\n", cryptFile.fileName, sizeof(cryptFile));

                // Write the encrypted file to .crypt file.
                if (!this->copyFileDataToFilePointer((string)cryptFile.fileName + ".enc", outputFile))
                        return false;

                // Delete the temporary file.
                if (!Utils::shredFile((string)cryptFile.fileName + ".enc")) {
                        printf("[-] Failed to shred the temp .enc file!\n");
                }

                if (!progressBar) {
                        printf("[*] Encrypted file data copy (%d bytes)\n", cryptFile.sizeFileData);
                }
        }

        if (progressBar)
                Utils::printProgressBar(1);

        // Encrypt the file info section. (CryptFile)
        // if (!this->encryptFileInfoSection(password, folderName + CRYPT_EXTENSION, sizeCryptFiles)) {

        // }
        
        fclose(outputFile);
        printf("\n[!] Locking finished!\n\n");

        // Or else it would be too much for our screen.
        if (folderList.size() < 8) {
                for (int i = 0; i < folderList.size(); i++) {

                        CryptFile cryptFile = folderList.at(i);
                        // Print out the file info.
                        printf("CryptFile [%d]\n", i);
                        printf("  Filename length:  %d\n", cryptFile.fileNameLen);
                        printf("  Filename:         %s\n", cryptFile.fileName);
                        printf("  isFolder:         %s\n", cryptFile.isFolder ? "True" : "False");
                        printf("  Enc. data size:   %ld\n", cryptFile.sizeFileData);
                        printf("  File key (hex):   %s\n", Utils::convertToHex(cryptFile.fileKey, 32).c_str());
                        printf("  File IV (hex):    %s\n", Utils::convertToHex(cryptFile.fileIV, 16).c_str());
                        printf("  File hash (MD5):  %s\n\n", Utils::convertToHex(cryptFile.fileHash, 16).c_str());
                }
        }

        printf("Size of cryptfiles: %ld\n", sizeCryptFiles);

        return true;
}      

bool Crypter::decryptFolder(CryptFileRead cryptFile, string folderName)
{
        if (mkdir(folderName.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1) {
                
                if (errno == EEXIST) {
                        printf("[-] Failed to create a new directory! Directory-name already exists %s!\n", folderName.c_str());
                }
                else if (errno == EACCES) {
                        printf("[-] Failed to create a new directory! Access denied!\n");
                }
                else {
                        printf("[-] Failed to create a new directory! Error code: %d\n", errno);
                }     
                return false; 
        }
        return true;
}

/**
 * @brief Loops trough the folder structure by the given parameter and returns 
 * a vector of CryptFile objects of the subfiles/folders of the folder.
 * 
 * @param folderName The foldername to look in to.
 * @return vector<Crypter::CryptFile> 
 */
vector<Crypter::CryptFile> Crypter::loopFolder(string folderName)
{
        vector<CryptFile> listFolder;
        listFolder.push_back(Crypter::generateCryptFolder(folderName));

        // Start looping the folder.
        DIR* dirHandler = opendir(folderName.c_str());
        if (dirHandler == 0) {

                printf("[-] Failed to open the directory for listing [%s]! Error code: %d\n", folderName.c_str(), errno);
                return vector<CryptFile>();
        }

        vector<string> folderListWait;

        struct dirent *fileHandler;
        while (fileHandler = readdir(dirHandler)) {

                if ((string)fileHandler->d_name == "." || (string)fileHandler->d_name == "..")
                        continue;
                
                if (fileHandler->d_type == DT_DIR) {

                        vector<CryptFile> list = loopFolder(folderName + "/" + fileHandler->d_name);

                        for (int i = 0; i < list.size(); i++) {
                                listFolder.push_back(list.at(i));
                        }
                }
                else {
                        listFolder.push_back(this->encryptFile(folderName + "/" + fileHandler->d_name, true));
                }
        }

        closedir(dirHandler);

        return listFolder;
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

                printf("[-] Failed to open the encrypted file %s! Error code: %d\n\n", fileName.c_str(), errno);
                return false;
        }

        /**
         * @brief sendfile() not possible here
         * 
         * The problem with this bit is that we want to copy the
         * file data to a certain offset in the output file. 
         * sendfile() doesn't support that for the offset, so we can't
         * use it for now.
         */

        // // To get the file size.
        // fseek(inputFile, 0, SEEK_END);
        // unsigned long fileSize = ftell(inputFile);
        // rewind(inputFile);

        // if (sendfile64(outputFile->_fileno, inputFile->_fileno, NULL, fileSize) == -1) {

        //         printf("[-] Failed to copy the bytes to output file! Error code: %d\n\n", errno);
        //         return false;  
        // }
        // return true;

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
                        printf("[-] Failed to write the file data into the output file! Error code: %d\n\n", errno);
                        return false;
                }
        
                totalBytes += readSize;
        }

        // Delete the encrypted file. 
        fclose(inputFile);
        free(buffer);
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
        // Get the offset to keep track on.
        __off64_t currentOffset = ftell(inputFile);

        if (sendfile64(outputFile->_fileno, inputFile->_fileno, &currentOffset,  fileSize) == -1) {
                printf("[-] Failed to copy the bytes from input file! Error code: %d\n\n", errno);
                return false;
        }

        // Adjust the offset again for the input file.
        fseek(inputFile, currentOffset, SEEK_SET);
        fclose(outputFile);

        return true;

        char* buffer = (char*)malloc(READ_SIZE);

        // When the size of the file is smaller than the read size.
        if (fileSize < READ_SIZE) {

                int readSize = fread(buffer, 1, fileSize, inputFile);
                if (readSize <= 0 && errno != 0) {
                        printf("[-] Failed to read buffer from input file! Error code: %d\n\n", errno);
                        return false;
                }

                if (fwrite(buffer, 1, readSize, outputFile) <= 0) {

                        printf("[-] Failed to write the input data to the output file! Error code: %d\n\n", errno);
                        return false;
                }   

                // Cleanup, WARNING: Do not close the inputFile, we still need it.
                free(buffer);
                fclose(outputFile);    
                return true; 
        }

        unsigned long counter = fileSize;
        while (counter != 0) {

                // Write data to output.
                int readSize;
                if (counter < READ_SIZE) {
                        readSize = fread(buffer, 1, counter, inputFile);
                        counter -= counter;
                }
                else {
                        readSize = fread(buffer, 1, READ_SIZE, inputFile);
                        counter -= READ_SIZE;
                }
              
                if (readSize <= 0) {

                        printf("[-] Failed to read buffer from input file! Error code: %d\n\n", errno);
                        return false;
                }
              
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
