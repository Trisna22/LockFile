#include "Crypter.h"

void usage() {
        string usageStr = "Usage: LockFile [options] <file>";
        printf("%s\n", usageStr.c_str());
}

void help() {
        usage();
        string helpStr = "\nOptions:\n";
        helpStr += "-i, --info                  Gets information about the encrypted file.\n";
        helpStr += "-c, --check                 Checks if file is an valid encrypted file from this tool.\n";
        helpStr += "-e, --encrypt               Encrypts the file with the crypter.\n";
        helpStr += "-d, --decrypt               Decrypts the file with the crypter.\n";
        helpStr += "-v, --version               Gets the version number from this tool.\n";
        helpStr += "\nAll rights served by ramb0 2021.\n";
        printf("%s\n", helpStr.c_str());
}

void version() {
        string versionStr = "\nAll rights served by ramb0 2021.\n";
        versionStr += "Version 1.0\n";
        printf("%s\n", versionStr.c_str());
}

int main(int argc, char*argv[]) {

        printf("LockFile 1.0 (c) ramb0 2021\n\n");

        if (argc < 2) {
                usage();
                return 0;
        }

        for (int i = 1; i < argc; i++) {

                string cmd = argv[i];
                if (cmd == "-h" || cmd == "--help") {
                        help();
                        return 0;
                }
                else {
                        string arg = argv[i];

                        Crypter crypter;
                        if ((arg == "-e" || arg == "--encrypt")&& argc == 3) {
                                crypter.createCryptFile(argv[2]);
                                return 0;
                        }
                        else if ((arg == "-i" || arg == "--info") && argc == 3) {
                                Crypter crypter;
                                crypter.readCryptHeader(argv[2]);
                                crypter.readCryptFiles(argv[2]);
                                return 0;
                        }
                        else if ((arg == "-d" || arg == "--decrypt") && argc == 3) {
                                Crypter crypter;
                                crypter.openCryptFile(argv[2]);
                                return 0;
                        }
                        else if ((arg == "-c" || arg == "--check") && argc == 3) {
                                Crypter crypter;
                                if (crypter.checkCryptFile(argv[2])) {

                                        printf("[!] Valid .crypt file!\n");
                                }
                                return 0;   
                        }
                        else if ((arg == "-h" || arg == "--help") && argc == 3) {
                                help();
                                return 0;
                        }
                        else if ((arg == "-v" || arg == "--version") && argc == 3) {
                                version();
                                return 0;
                        }       
                        else {
                                printf("Invalid (combination of) options or arguments given!\n");
                                usage();
                                return 0;
                        }
                }
        }
        
	return 0;
}
/**
 * @brief 
 * Options:
 * 
 * -i info
 * -e encrypt
 * -d decrypt
 * -v version
 * -c validate
 */

// Test example encrypting strings with RSA.
/*
RSACrypter RSAcrypter;
RSAcrypter.generateKeys();

int sizeCipher;
unsigned char* cipherText = RSAcrypter.encryptData((char*)"The brown fox jumps over the white fox...", 42, &sizeCipher);
if (cipherText == NULL) {

        printf("# Failed to encrypt with RSA!\n\n");
        return 1;
}

printf("\nCipher size:  %d\n", sizeCipher);
printf("Cipher text: %s\n", Crypter::convertToHex((char*)cipherText, sizeCipher).c_str());

int sizePlainText;
unsigned char* plainText = RSAcrypter.decryptData((char*)cipherText, sizeCipher, &sizePlainText);
if (plainText == NULL) {
        printf("# Failed to decrypt with RSA!\n\n");
        return 1;
}

printf("\nPlaintext size: %d\n", sizePlainText);
printf("Plaintext data: %s\n", plainText);
*/

// Test example encrypting files.
/*
// Testing purposes only:
AESCrypter aesCrypter;
aesCrypter.setKey("ThisIsAStrongPassword", 22);

FILE* inputFile = fopen("./netcon", "rb");
if (inputFile == NULL) {

        printf("# Failed to open input file! Error code: %d\n\n", errno);
        return 0;
}

FILE* outputFile = fopen("./netcon.enc", "wb");
if (outputFile == NULL) {
        
        printf("# Failed to open output file! Error code: %d\n\n", errno);
        return 0;
}

unsigned long totalBytes;
aesCrypter.encryptFile(inputFile, outputFile, &totalBytes);
printf("[*] Written a total of %ld bytes!\n\n", totalBytes);
/////////////////////////////////////////////////////////////////
aesCrypter.setKey("ThisIsAStrongPassword", 22, aesCrypter.getIv(), true);


FILE* inputFile2 = fopen("./netcon.enc", "rb");
if (inputFile2 == NULL) {

        printf("# Failed to open the encrypted file! Error code: %d\n", errno);
        return 0;
}

FILE* outputFile2 = fopen("./netcon.dec", "wb");
if (outputFile2 == NULL) {

        printf("# Failed to open the decrypting file! Error code: %d\n", errno);
        return 0;
}
unsigned long totalBytes2;
aesCrypter.decryptFile(inputFile2, outputFile2, &totalBytes2);

printf("[*] Written a total of %ld bytes!\n", totalBytes2);
return 1;
*/

// Test example encrypting strings with AES.
/*
AESCrypter aesCrypter;
aesCrypter.setKey("ThisIsAStrongPassword", 22);
int sizeCipherText; 
unsigned char* cipherText = aesCrypter.encryptData("The brown fox jumps over the white fox...", 43, &sizeCipherText);
if (cipherText == NULL) {

        printf("# Failed to encrypt data!\n\n");
        return 0;
}

printf("Ciphertext: %s\n", AESCrypter::convertToHex((char*)cipherText, sizeCipherText).c_str());
printf("Size ciphertext (unhexxed): %d\n", sizeCipherText);

// Decrypttinggg.
aesCrypter.setKey("ThisIsAStrongPassword", 22, aesCrypter.getIv(), true);

int sizePlainText;
unsigned char* plainText = aesCrypter.decryptData((char*)cipherText, sizeCipherText, &sizePlainText);
if (plainText == NULL) {

        printf("# Failed to decrypt data!\n\n");
        return 0;
}

printf("\nPlainText: %s\n", plainText);
printf("Size nsigned char* cipherText = aesCrypter.encryptData("The brown fox jumps over the white fox...", 43, &sizeCipherText);
if (cipherText == NULL) {

        printf("# Failed to encrypt data!\n\n");
        return 0;
}

printf("Ciphertext: %s\n", AESCrypter::convertToHex((char*)cipherText, sizeCipherText).c_str());
printf("Size ciphertext (unhexxed): %d\n", sizeCipherText);

// Decrypttinggg.
aesCrypter.setKey("ThisIsAStrongPassword", 22, aesCrypter.getIv(), true);

int sizePlainText;
unsigned char* plainText = aesCrypter.decryptData((char*)cipherText, sizeCipherText, &sizePlainText);
if (plainText == NULL) {

        printf("# Failed to decrypt data!\n\n");
        return 0;
}

printf("\nPlainText: %s\n", plainText);
printf("Size plaintext: %d\n", sizePlainText);
*/
