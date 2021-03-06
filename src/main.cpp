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
        helpStr += "-q, --quiet                 No output, only when an error pops up.\n";
        helpStr += "-r, --remove                Deletes the original file/folder with our shredder.\n";
        helpStr += "\nAll rights served by ramb0 2021.\n";
        printf("%s\n", helpStr.c_str());
}

void version() {
        string versionStr = "\nAll rights served by ramb0 2022.\n";
        versionStr += "Version 1.0\n";
        versionStr += "Version hash ";
        versionStr += VERSION_HASH;
        versionStr += "\n";
        printf("%s\n", versionStr.c_str());
}

int main(int argc, char*argv[]) {

        printf("LockFile 1.0 (c) ramb0 2021-2022\n\n");

        if (argc < 2) {
                usage();
                return 0;
        }

        Crypter crypter;
        for (int i = 1; i < argc; i++) {

                string arg = argv[i];

                if ((arg == "-e" || arg == "--encrypt")&& i < argc) {
                        crypter.createCryptFile(argv[i +1], Utils::requirePassword());
                        return 0;
                }
                else if (arg == "-q" || arg == "--quiet") {
                        crypter.setQuiet();
                        continue;
                }
                else if (arg == "-r" || arg == "--remove") {
                        crypter.setRemove();
                        continue;
                }
                else if ((arg == "-i" || arg == "--info") && i < argc) {

                        char* passPhrase = Utils::requirePassword();
                        crypter.readCryptHeader(argv[i +1], passPhrase);
                        crypter.readCryptFiles(argv[i +1], passPhrase);
                        return 0;
                }
                else if ((arg == "-d" || arg == "--decrypt") && i < argc) {

                        crypter.openCryptFile(argv[i+1], Utils::requirePassword());
                        return 0;
                }
                else if ((arg == "-c" || arg == "--check") && i < argc) {

                        if (crypter.checkCryptFile(argv[i+1])) {

                                printf("[!] Valid .crypt file!\n");
                        }
                        return 0;   
                }
                else if (arg == "-h" || arg == "--help") {
                        help();
                        return 0;
                }
                else if (arg == "-v" || arg == "--version") {
                        version();
                        return 0;
                }       
                else {
                        printf("Invalid (combination of) options or arguments given!\n");
                        usage();
                        return 0;
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
