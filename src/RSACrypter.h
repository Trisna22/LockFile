
#include "stdafx.h"
#include "Crypter.h"

#ifndef RSACrypter_H
#define RSACrypter_H

#define KEY_LENGTH              2048

#define LOG_ALL

class RSACrypter {
public:
        RSACrypter();
        bool generateKeys();
        char* getPublicKey(int *lenPublicKey);
        char* getPrivateKey(int *lenPrivateKey);

        unsigned char* encryptData(char* data, int sizeData, int *sizeOutput);
        unsigned char* decryptData(char* data, int sizeData, int *sizeOutput);
private:
        RSA* keyPair;
        char* privateKey, *publicKey;
        int lenPrivateKey, lenPublicKey;
};

#endif // !RSACrypter_H

RSACrypter::RSACrypter()
{

}

/**
 * @brief Generates the public and private keys.
 */
bool RSACrypter::generateKeys()
{
        printf("[*] Generating RSA (%d bits) keypair...\n", KEY_LENGTH);
        this->keyPair = RSA_generate_key(KEY_LENGTH, 3, NULL, NULL);
        if (keyPair == NULL) {

                printf("# Failed to generate keypair!\n");
                ERR_load_crypto_strings();
                char* err;
                ERR_error_string(ERR_get_error(), err);
                printf("%s\n", err);
                return false;
        }

        BIO *pri = BIO_new(BIO_s_mem());
        BIO *pub = BIO_new(BIO_s_mem());

        PEM_write_bio_RSAPrivateKey(pri, keyPair, NULL, NULL, 0, NULL, NULL);
        PEM_write_bio_RSAPublicKey(pub, keyPair);

        this->lenPrivateKey = BIO_pending(pri);
        this->lenPublicKey = BIO_pending(pub);

        this->privateKey = (char*)malloc(this->lenPrivateKey + 1);
        this->publicKey = (char*)malloc(this->lenPublicKey + 1);

        BIO_read(pri, this->privateKey, this->lenPrivateKey);
        BIO_read(pub, this->publicKey, this->lenPublicKey);
        
        this->privateKey[this->lenPrivateKey] = '\0';
        this->publicKey[this->lenPublicKey] = '\0';

        #ifdef LOG_ALL
                printf("\n%s\n%s", this->privateKey, this->publicKey);
        #endif

        return true;
}

/**
 * @brief Returns the public key char array.
 * 
 * @param lenPublicKey 
 * @return char* 
 */
char* RSACrypter::getPublicKey(int* lenPublicKey)
{
        *lenPublicKey = this->lenPublicKey;
        this->publicKey;
}

/**
 * @brief Returns the private key char array.
 * 
 * @param lenPrivateKey 
 * @return char* 
 */
char* RSACrypter::getPrivateKey(int* lenPrivateKey)
{
        *lenPrivateKey = this->lenPrivateKey;
        return this->privateKey;
}

unsigned char* RSACrypter::encryptData(char* data, int sizeData, int *sizeOutput)
{
        unsigned char* cipherOutput = (unsigned char*)malloc(RSA_size(this->keyPair));

        if ((*sizeOutput = RSA_public_encrypt(strlen(data) + 1, (unsigned char*)data, cipherOutput,
                keyPair, RSA_PKCS1_OAEP_PADDING)) == -1) {
                
                char* err = (char*)malloc(130);
                ERR_load_crypto_strings();
                ERR_error_string(ERR_get_error(), err);
                printf("# Failed to encrypt the data! Error code: %d\n", errno);
                return NULL;
        }

        return cipherOutput;
}

unsigned char* RSACrypter::decryptData(char* data, int sizeData, int *sizeOutput)
{
        unsigned char* plainText = (unsigned char*)malloc(sizeData);
        if ((*sizeOutput = RSA_private_decrypt(sizeData, (unsigned char*)data, plainText, 
                keyPair, RSA_PKCS1_OAEP_PADDING)) == -1) {
                
                char* err = (char*)malloc(130);
                ERR_load_crypto_strings();
                ERR_error_string(ERR_get_error(), err);
                printf("# Failed to decrypt the data! Error code: %d\n", errno);
                return NULL;
        }

        return plainText;
}

// https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-openssl/
