#include "stdafx.h"
#include "Utils.h"

#ifndef AESCrypter_H
#define AESCrypter_H

#define BLOCK_SIZE 4096
#define BUFSIZE 1024

/* 32 byte key (256 bit key) */
#define AES_256_KEY_SIZE 32
/* 16 byte block size (128 bits) */
#define AES_BLOCK_SIZE 16

class AESCrypter {
public:
        AESCrypter();
        ~AESCrypter();
        void createRandomKey(unsigned char*);
        void setIv(unsigned char*);
        void setIv2(unsigned char*);
        unsigned char* getIv();
        bool setKey(unsigned char* key, int keyLen, unsigned char* iv, bool decrypt);

        unsigned char* encryptData(char* data, int sizeData, int *sizeOutput);
        unsigned char* decryptData(char* data, int sizeData, int* sizeOutput);
        bool encryptDecryptFile(FILE* inputFile, FILE* outputFile, unsigned long* sizeOutput);

private:
        EVP_CIPHER_CTX* cipherContext;
        const EVP_CIPHER* encryptionMethod = EVP_aes_256_cbc_hmac_sha256();
        unsigned char IV[16];

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
        EVP_CIPHER_CTX_set_padding(this->cipherContext, BUFSIZE);
}

AESCrypter::~AESCrypter()
{
        EVP_CIPHER_CTX_free(this->cipherContext);
}

void AESCrypter::createRandomKey(unsigned char* key)
{
        unsigned char randomKey[32];
        RAND_bytes(randomKey, 32);

        for (int i = 0; i < 32; i++)
                key[i] = randomKey[i];
}

void AESCrypter::setIv(unsigned char* iv)
{
        for (int i = 0; i < 16; i++)
                iv[i] = this->IV[i];
}

void AESCrypter::setIv2(unsigned char* iv)
{
        for (int i = 0; i < 16; i++)
                this->IV[i] = iv[i];

}

unsigned char* AESCrypter::getIv() {
        return this->IV;
}

bool AESCrypter::setKey(unsigned char* passedKey, int lenKey, unsigned char* passedIV = NULL, bool decrypt = false)
{
        // Find out how long the key size can be.                                                               
        if (lenKey > AES_256_KEY_SIZE) {
                printf("# Provided password too long, max of 32 characters!\n");
                return false;
        }


        unsigned char key[AES_256_KEY_SIZE];

        if (lenKey < AES_256_KEY_SIZE) {
                for (int i = 0; i < lenKey; i++) // Minus 1 for the null byte.
                        key[i] = passedKey[i];
                for (int i = lenKey; i < AES_256_KEY_SIZE; i++)
                        key[i] = 'X';
        }
        else
                memcpy(key, passedKey, AES_256_KEY_SIZE);

        if (!decrypt) {
                // Generate random IV.
                unsigned char iv_enc[AES_BLOCK_SIZE];
                RAND_bytes(iv_enc, AES_BLOCK_SIZE);
                memcpy(this->IV, iv_enc, 16);

                /* Don't set key or IV right away; we want to check lengths */
                if(!EVP_CipherInit_ex(this->cipherContext, encryptionMethod, NULL, NULL, NULL, 1)){
                        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", 
                        ERR_error_string(ERR_get_error(), NULL));
                        return false;
                }

                OPENSSL_assert(EVP_CIPHER_CTX_key_length(this->cipherContext) == AES_256_KEY_SIZE);
                OPENSSL_assert(EVP_CIPHER_CTX_iv_length(this->cipherContext) == AES_BLOCK_SIZE);

                /* Now we can set key and IV */
                // this->IV
                if(!EVP_CipherInit_ex(this->cipherContext, NULL, NULL, (unsigned char*)"XXXXXXXXXXXXXXXX", key, 1)){
                        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", 
                        ERR_error_string(ERR_get_error(), NULL));
                        return false;
                }
        }
        else {
                //this->IV = passedIV; // IV from parameter.

                /* Don't set key or IV right away; we want to check lengths */
                if(!EVP_CipherInit_ex(this->cipherContext, encryptionMethod, NULL, NULL, NULL, 0)){
                        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", 
                        ERR_error_string(ERR_get_error(), NULL));
                        return false;
                }

                OPENSSL_assert(EVP_CIPHER_CTX_key_length(this->cipherContext) == AES_256_KEY_SIZE);
                OPENSSL_assert(EVP_CIPHER_CTX_iv_length(this->cipherContext) == AES_BLOCK_SIZE);

                /* Now we can set key and IV */
                // passedIV

                if(!EVP_CipherInit_ex(this->cipherContext, NULL, NULL, (unsigned char*)"XXXXXXXXXXXXXXXX", key, 0)){
                        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", 
                        ERR_error_string(ERR_get_error(), NULL));
                        return false;
                }
        }

        return true;
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

bool AESCrypter::encryptDecryptFile(FILE* inputFile, FILE* outputFile, unsigned long* sizeOutput)
{
        // Allow enough space in output buffer for additional block.
        int cipher_block_size = EVP_CIPHER_block_size(this->encryptionMethod);
        unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];

        int num_bytes_read, out_len;
        *sizeOutput = 0;

        ...; // Check the max malloc size, so that we can encrypt in memory.

        for (;;) {

                // Read in data in blocks until EOF. Update the ciphering with each read.
                num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, inputFile);
                if (ferror(inputFile)){
                        fprintf(stderr, "# Failed to read bytes from file! Error: %s\n", strerror(errno));
                        fclose(outputFile);
                        return false;
                } 

                if(!EVP_CipherUpdate(this->cipherContext, out_buf, &out_len, in_buf, num_bytes_read)){
                        fprintf(stderr, "# Failed to update cipher block. OpenSSL error: %s\n", 
                                ERR_error_string(ERR_get_error(), NULL));
                        fclose(outputFile);
                        return false;
                }

                fwrite(out_buf, sizeof(unsigned char), out_len, outputFile);
                if (ferror(outputFile)) {
                        fprintf(stderr, "# Failed to write data to file! Error: %s\n", strerror(errno));
                        fclose(outputFile);
                        return false;
                }
                
                *sizeOutput += out_len;
                if (num_bytes_read < BUFSIZE) {
                        // Reached end of file.
                        break;
                }
        }

        // Now cipher the final block and write it out to file.
        if(!EVP_CipherFinal_ex(this->cipherContext, out_buf, &out_len)) {
                fprintf(stderr, "# Failed to finalize cipher! OpenSSL error: %s\n", 
                        ERR_error_string(ERR_get_error(), NULL));
                fclose(outputFile);
                return false;
        }

        fwrite(out_buf, sizeof(unsigned char), out_len, outputFile);

        if (ferror(outputFile)) {
                fprintf(stderr, "# Failed to write the last bits to file! Error: %s\n", strerror(errno));
                fclose(outputFile);
                return false;
        }      
        *sizeOutput += out_len;

        fclose(outputFile);
        fclose(inputFile);

        return true;
}

void AESCrypter::string_to_uchar(string str, unsigned char* charArr)
{
        strncpy((char*)charArr, str.c_str(), str.length());
}



// Backup encryptFile()/decryptFile() functions.
/*      
bool AESCrypter::encryptFile(FILE* inputFile, FILE* outputFile, unsigned long* sizeOutput)
{
        unsigned char* inputBuffer = (unsigned char*)malloc(BLOCK_SIZE);
        unsigned char* outputBuffer = (unsigned char*)malloc(BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH);
        int outputBufferSize;
        *sizeOutput = 0;

        for (;;) {
                int readSize = fread(inputBuffer, 1, BLOCK_SIZE, inputFile);
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
        unsigned char* inputBuffer = (unsigned char*)malloc(BLOCK_SIZE);
        unsigned char* outputBuffer = (unsigned char*)malloc(BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH);
        int outputBufferSize;
        *sizeOutput = 0;

        for (;;) {
                int readSize = fread(inputBuffer, 1, BLOCK_SIZE, inputFile);
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
        // EVP_DecryptFinal_ex() always returns zero, even if it decrypted correctly.
        int tempLen;
        EVP_DecryptFinal_ex(this->cipherContext, outputBuffer + outputBufferSize, &tempLen); 
        /*{

                printf("# Failed to finalize the decrypted data!\n\n");
                ERR_print_errors_fp(stderr);
                return false;
        }

        // Somehow we miss a few bytes at the end of binary files!
        // Maybe this is bc of the block sizes.

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

        free(inputBuffer);
        free(outputBuffer);
        fclose(inputFile);
        fclose(outputFile);
        return true;
}
*/