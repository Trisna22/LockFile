#include "stdafx.h"

#ifndef Crypter_H
#define Crypter_H

class Crypter {
public:
	Crypter();
        ~Crypter();
	bool checkCryptFile(string fileName);
        bool createCryptFile(string target);

        static string convertToHex(char* arr, int size);
        static char* convertToBinary(string data);
private:
	bool encryptFile(string fileName);
	bool decryptFile(string fileName);

        bool encryptFolder(string fileName);
        bool decryptFolder(string fileName);

        typedef struct {
                char magic[4];
                unsigned int sizePrivateKey;
                char* encryptedPrivateKey;
                unsigned int sizeIv;
                char* iv;
                unsigned long sizeFileData;
                char* fileData;

        } ENCRYPTION_FILE;

        bool isFolder;
};

#endif // !Crypter_H

Crypter::Crypter()
{

}

Crypter::~Crypter()
{

}

bool Crypter::checkCryptFile(string fileName)
{
        // Check magic bytes.
        return false;
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

                printf("<*> Failed to create crypt file! Error code: %d\n\n", errno);
                return false;
        }
}

string Crypter::convertToHex(char* arr, int size)
{
        stringstream ss;
        ss << hex << std::setfill('0');
        for (size_t i = 0; size > i; ++i)
        {
                ss << setw(2) << static_cast<unsigned int>(
                        static_cast<unsigned char>(arr[i]));
        }
        string result = ss.str();
        ss.clear();
        return result;
}
char* Crypter::convertToBinary(string data)
{
        int len = data.length();
        char* newArr = new char[data.length() / 2 +1]; // Divided by 2 bc it is hex to bytes.
        int counter = 0;
        for (int i = 0; i < len; i += 2)
        {
                string byte = data.substr(i, 2); 
                char chr = (char) (int) strtol(byte.c_str(), 0, +16);
                newArr[counter++] = chr;
        }
        newArr[counter] = '\0'; // To put the string termination at the end.
        return newArr;
}

/////////// private member functions ///////////////

bool Crypter::encryptFile(string fileName)
{
        // First generate RSA key for all our files.

        // Encrypt the RSA key with our password.

        // Encrypt all files with our RSA key.

        // Save encrypted RSA key and files in single file
        // with headers like magic bytes, file size, 
        return false;
}

bool Crypter::decryptFile(string fileName)
{
        return false;
}

bool Crypter::encryptFolder(string fileName)
{
        return false;
}      

bool Crypter::decryptFolder(string fileName)
{
        return false;
}