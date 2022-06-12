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

#define CIPHER_METHOD EVP_aes_256_cbc_hmac_sha256()

class AESCrypter {
public:
        AESCrypter();
        ~AESCrypter();
        static void createRandomKey(unsigned char*);
        bool setKey(unsigned char* key, int keyLen, unsigned char* iv, bool decrypt);

        bool encryptFile(FILE* inputFile, FILE* outputFile, unsigned long* sizeOutput);
        bool decryptFile(FILE* inputFile, FILE* outputFile, off64_t* sizeInput);

        unsigned char* encryptDecryptData(unsigned char* data, int *sizeData);
        unsigned char* finalData(int* sizeData);


        static unsigned long getOutputSizeOf(string fileName);

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


bool AESCrypter::encryptFile(FILE* inputFile, FILE* outputFile, unsigned long* sizeOutput)
{       
        // Allow enough space in output buffer for additional block.
        int cipher_block_size = EVP_CIPHER_block_size(this->encryptionMethod);
        unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
        
        int num_bytes_read, out_len;
        *sizeOutput = 0;

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

        fclose(inputFile);
        return true;
}

bool AESCrypter::decryptFile(FILE* inputFile, FILE* outputFile, off64_t *sizeInput)
{
        // Allow enough space in output buffer for additional block.
        int cipher_block_size = EVP_CIPHER_block_size(this->encryptionMethod);
        unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
        
        int num_bytes_read, out_len;
        off64_t counter = *sizeInput;

        while (counter != 0) {

                if (counter < BUFSIZE)
                        num_bytes_read = fread(in_buf, sizeof(unsigned char), counter, inputFile);
                else 
                        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, inputFile);

                if (num_bytes_read <= 0) {
                        fprintf(stderr, "# Failed to read data for file!  Error: %s\n", strerror(errno));
                        fclose(outputFile);
                        return false;
                }

                // Read in data in blocks until EOF. Update the ciphering with each read.
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

                counter -= num_bytes_read; // We want to count the encrypted bytes, not the output bytes.
                if (counter == 0 || counter <= 0)
                        break;
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

        fclose(outputFile);
        return true;
}

unsigned char* AESCrypter::encryptDecryptData(unsigned char* data,  int *sizeData) 
{
        int out_len, cipher_block_size = EVP_CIPHER_block_size(this->encryptionMethod);
        unsigned char* out_buf = new unsigned char[BUFSIZ + cipher_block_size];

        if (!EVP_CipherUpdate(this->cipherContext, out_buf, &out_len, data, *sizeData)) {

                printf("# Failed encrypt our plaintext with AES!\n\n");
                ERR_print_errors_fp(stderr);
                return NULL;
        }

        *sizeData = out_len;
        return out_buf;
}

unsigned char* AESCrypter::finalData(int* sizeData) 
{
        int cipher_block_size = EVP_CIPHER_block_size(this->encryptionMethod);
        unsigned char* out_buf = new unsigned char[BUFSIZE + cipher_block_size];
        if(!EVP_CipherFinal_ex(this->cipherContext, out_buf, sizeData)) {

                fprintf(stderr, "# Failed to finalize cipher! OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
                return NULL;
        }

        return out_buf;
}

unsigned long AESCrypter::getOutputSizeOf(string fileName)
{
        int cipher_block_size = EVP_CIPHER_block_size(CIPHER_METHOD);
        unsigned long outputSize;
                
        unsigned long fileSize = Utils::getFileSize(fileName);
        if (fileSize == 0)
                return fileSize;

        if (fileSize % cipher_block_size == 0) {
                int times = (fileSize / cipher_block_size) + 1;
                outputSize = times* cipher_block_size;
        } else
                outputSize = fileSize + (cipher_block_size - (fileSize % cipher_block_size));

        return outputSize;
}

void AESCrypter::string_to_uchar(string str, unsigned char* charArr)
{
        strncpy((char*)charArr, str.c_str(), str.length());
}

