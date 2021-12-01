// Encrypt/Decrypt AES
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

#include "stdafx.h"
#include "Crypter.h"

#ifndef AESCrypter_H
#define AESCrypter_H

class AESCrypter {
public:
        AESCrypter();
        ~AESCrypter();
        bool setKey(string key, int keyLen, string iv, bool decrypt);
        string getIv();

        unsigned char* encryptData(char* data, int sizeData, int *sizeOutput);
        unsigned char* decryptData(char* data, int sizeData, int* sizeOutput);
        bool encryptFile(FILE* inputFile, FILE* outFile, unsigned long* sizeOutput);
        bool decryptFile(FILE* outputFile, FILE* outFile, unsigned long* sizeOutput);
private:
        EVP_CIPHER_CTX* cipherContext;
        const EVP_CIPHER* encryptionMethod = EVP_aes_256_cbc();
        string IV;

        static void string_to_uchar(string str, unsigned char* charArr);
};

#endif // !AESCrypter_H

AESCrypter::AESCrypter()
{
        // Create cipher context.
        if (!(this->cipherContext = EVP_CIPHER_CTX_new())) {

                printf("# Failed to initialize the cipher context!\n\n");
                ERR_print_errors_fp(stderr);
                return;
        }

        // No padding.
        EVP_CIPHER_CTX_set_padding(this->cipherContext, 0);
}

AESCrypter::~AESCrypter()
{
        EVP_CIPHER_CTX_free(this->cipherContext);
}

bool AESCrypter::setKey(string key, int lenKey, string strIV = "", bool decrypt = false)
{
        // Generate random IV.
        unsigned char iv_enc[AES_BLOCK_SIZE];
        RAND_bytes(iv_enc, AES_BLOCK_SIZE);

        // Find out how long the key size can be.                                                               
        if (lenKey > 32) {
                printf("# Provided password too long, max of 32 characters!\n");
                return false;
        }

        string oldKey = key;
        key.clear();
        if (lenKey < 32) {
                for (int i = 0; i < lenKey -1; i++) // Minus 1 for the null byte.
                        key.push_back(oldKey[i]);
                for (int i = lenKey; i < 32; i++)
                        key.push_back('X');
        }

        if (decrypt == false) {

                this->IV = Crypter::convertToHex((char*)iv_enc, 16);

                if (EVP_EncryptInit_ex(this->cipherContext, encryptionMethod, NULL, (unsigned char*)key.c_str(), iv_enc) == 0) {

                        printf("# Failed initialize encryption AES in our context!\n\n");
                        ERR_print_errors_fp(stderr);
                        return false;
                }

        }
        else {
                this->IV = strIV; // IV from parameter.

                char* decodedIV = Crypter::convertToBinary(strIV);
                if (EVP_DecryptInit_ex(this->cipherContext, encryptionMethod, NULL, (unsigned char*)key.c_str(), (unsigned char*)decodedIV) == 0) {
                        printf("# Failed initialize decryption AES in our context!\n\n");
                        ERR_print_errors_fp(stderr);
                        return false;
                }
        }

        return true;
}

string AESCrypter::getIv() {
        return this->IV;
}

unsigned char* AESCrypter::encryptData(char* data, int sizeData, int *sizeOutput) 
{
        unsigned char* output;
        int cipherLen;
               
        printf("\nPlaintext: %s\n", data);
        printf("Plaintext size: %d\n\n", sizeData);

        if (!EVP_EncryptUpdate(this->cipherContext, output, &cipherLen, (unsigned char*)data, sizeData+1)) {
                printf("# Failed encrypt our plaintext with AES!\n\n");
                ERR_print_errors_fp(stderr);
                return NULL;
        }

        *sizeOutput = cipherLen;
        if (!EVP_EncryptFinal_ex(this->cipherContext, output + cipherLen, sizeOutput)) {
                printf("# Failed finalize our ciphertext with AES!\n\n");
                ERR_print_errors_fp(stderr);
                return NULL;
        }

        *sizeOutput += cipherLen;
        return output;
}

unsigned char* AESCrypter::decryptData(char* data, int sizeData, int *sizeOutput) 
{
        printf("Ciphertext: %s\n", data);
        printf("Size cipher: %d\n", sizeData);
        unsigned char* output;
        int plaintextLen;

        if (!EVP_DecryptUpdate(this->cipherContext, output, &plaintextLen, (unsigned char*)data, sizeData)) {
                printf("# Failed decrypt our ciphertext with AES!\n\n");
                ERR_print_errors_fp(stderr);
                return NULL;
        }

        *sizeOutput = plaintextLen;
        if (!EVP_DecryptFinal_ex(this->cipherContext, output + plaintextLen, sizeOutput)) {
                printf("# Failed finalize our ciphertext with AES!\n\n");
                ERR_print_errors_fp(stderr);
                return NULL;
        }

        *sizeOutput += plaintextLen;
        return output;
}
        
bool AESCrypter::encryptFile(FILE* inputFile, FILE* outputFile, unsigned long* sizeOutput)
{
        long blockSize = 1024;

        unsigned char* inputBuffer = (unsigned char*)malloc(blockSize);
        unsigned char* outputBuffer = (unsigned char*)malloc(blockSize + EVP_MAX_BLOCK_LENGTH);
        int outputBufferSize;
        *sizeOutput = 0;

        for (;;) {
                int readSize = fread(inputBuffer, 1, blockSize, inputFile);
                if (readSize <= 0 && errno != 0) {

                        printf("# Failed to read buffer from input file! Error code: %d\n\n", errno);
                        return false;
                }
                else if (readSize <= 0 && errno == 0)
                        break;

                if (!EVP_EncryptUpdate(this->cipherContext, outputBuffer, &outputBufferSize,
                 inputBuffer, readSize)) {
                        printf("# Failed to update the input buffer!\n\n");
                        ERR_print_errors_fp(stderr);
                        return false;
                }

                if (fwrite(outputBuffer, 1, outputBufferSize, outputFile) <= 0) {

                        printf("# Failed to write the encrypted data to output file! Error code: %d\n\n", errno);
                        return false;
                }
                
                *sizeOutput += outputBufferSize; // Add the byte count to the pointer.
        }

        // Finalizing encrypted data.
        int tempLen;
        if (!EVP_EncryptFinal_ex(this->cipherContext, outputBuffer + outputBufferSize, &tempLen)) {

                printf("# Failed to finalize the encrypted data!\n\n");
                ERR_print_errors_fp(stderr);
                return false;
        }

        *sizeOutput += tempLen; // Last update of byte count pointer.

        // Last write.
        if (fwrite(outputBuffer, 1, tempLen, outputFile) <= 0) {

                printf("# Failed to write the final encrypted data to output file! Error code: %d\n\n", errno);
                return false;
        }

        fclose(inputFile);
        fclose(outputFile);
        return true;
}
bool AESCrypter::decryptFile(FILE* inputFile, FILE* outputFile, unsigned long* sizeOutput)
{
        long blockSize = 1024;

        unsigned char* inputBuffer = (unsigned char*)malloc(blockSize);
        unsigned char* outputBuffer = (unsigned char*)malloc(blockSize + EVP_MAX_BLOCK_LENGTH);
        int outputBufferSize;
        *sizeOutput = 0;

        for (;;) {
                int readSize = fread(inputBuffer, 1, blockSize, inputFile);
                if (readSize <= 0 && errno != 0) {

                        printf("# Failed to read buffer from input file! Error code: %d\n\n", errno);
                        return false;
                }
                else if (readSize <= 0 && errno == 0)
                        break;

                if (!EVP_DecryptUpdate(this->cipherContext, outputBuffer, &outputBufferSize,
                 inputBuffer, readSize)) {
                        printf("# Failed to update the input buffer!\n\n");
                        ERR_print_errors_fp(stderr);
                        return false;
                }

                if (fwrite(outputBuffer, 1, outputBufferSize, outputFile) <= 0) {

                        printf("# Failed to write the decrypted data to output file! Error code: %d\n\n", errno);
                        return false;
                }
                
                *sizeOutput += outputBufferSize; // Add the byte count to the pointer.
        }

        // Finalizing encrypted data.
        int tempLen;
        EVP_DecryptFinal_ex(this->cipherContext, outputBuffer + outputBufferSize, &tempLen);
        // EVP_DecryptFinal_ex() always returns zero, even if it decrypted correctly.
        /*{

                printf("# Failed to finalize the decrypted data!\n\n");
                ERR_print_errors_fp(stderr);
                return false;
        }*/

        *sizeOutput += tempLen; // Last update of byte count pointer.

        // If there are any bytes to write to.
        if (tempLen != 0) {
                // Last write.
                if (fwrite(outputBuffer, 1, tempLen, outputFile) <= 0) {

                        printf("# Failed to write the final decrypted data to output file! Error code: %d\n\n", errno);
                        return false;
                }
        }

        *sizeOutput += outputBufferSize;

        fclose(inputFile);
        fclose(outputFile);
        return true;
}

void AESCrypter::string_to_uchar(string str, unsigned char* charArr)
{
        strncpy((char*)charArr, str.c_str(), str.length());
}


/*
int do_crypt(FILE *in, FILE *out, int do_encrypt)
 {
     /* Allow enough space in output buffer for additional block */
     /*unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
     int inlen, outlen;
     EVP_CIPHER_CTX *ctx;
     /*
      * Bogus key and IV: we'd normally set these from
      * another source.
      */
     /*
     unsigned char key[] = "0123456789abcdeF";
     unsigned char iv[] = "1234567887654321";

     /* Don't set key or IV right away; we want to check lengths */
     /*
     ctx = EVP_CIPHER_CTX_new();
     EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
                       do_encrypt);
     OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
     OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

     /* Now we can set key and IV */
    /* EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

     for (;;) {
         inlen = fread(inbuf, 1, 1024, in);
         if (inlen <= 0)
             break;
         if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
             EVP_CIPHER_CTX_free(ctx);
             return 0;
         }
         fwrite(outbuf, 1, outlen, out);
     }
     if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
         EVP_CIPHER_CTX_free(ctx);
         return 0;
     }
     fwrite(outbuf, 1, outlen, out);

     EVP_CIPHER_CTX_free(ctx);
     return 1;
 }

*/