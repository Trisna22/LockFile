#include "stdafx.h"

#ifndef RSACrypter_H
#define RSACrypter_H

#define KEY_LENGTH              2048

#define LOG_ALL

class RSACrypter {
public:
        RSACrypter();
        bool generateKeys(string passphrase);
        char* getPublicKey(int *lenPublicKey);
        char* getPrivateKey(int *lenPrivateKey);
        bool setPrivateKey(char* privateKey, unsigned int sizeKey, string passphrase);

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
bool RSACrypter::generateKeys(string passPhrase)
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
        if (pri == NULL || pub == NULL) {
                printf("# Failed to generate memory BIO's for private and public keys! Error code: %d\n\n", errno);
                return false;
        }

        /**
         * @brief 
         * Really checkout the man pages
         * In the examples there is one which does what we want!!!
         * 
         * Sources:
         * https://man.netbsd.org/SSL_CTX_set_default_passwd_cb.3
         * https://www.openssl.org/docs/man1.1.1/man3/PEM_write_bio_RSAPrivateKey.html
         * https://linux.die.net/man/3/pem_write_pkcs8privatekey
         **/

        // Writing private key with encryption of AES with our passphrase.
        if (!PEM_write_bio_RSAPrivateKey(pri, keyPair, EVP_aes_256_cbc(), NULL, 0, NULL, (void*)passPhrase.c_str())) {
                printf("# Failed to write the private key to thEVP_aes__cbce allocated memory BIO! Error code: %d\n\n", errno);
                return false;
        }        
        
        if (!PEM_write_bio_RSAPublicKey(pub, keyPair)) {
                printf("# Failed to write the public key to the allocated memory BIO! Error code: %d\n\n", errno);
                return false;
        }

        this->lenPrivateKey = BIO_pending(pri);
        this->lenPublicKey = BIO_pending(pub);

        this->privateKey = (char*)malloc(this->lenPrivateKey + 1);
        this->publicKey = (char*)malloc(this->lenPublicKey + 1);

        BIO_read(pri, this->privateKey, this->lenPrivateKey);
        BIO_read(pub, this->publicKey, this->lenPublicKey);
        
        this->privateKey[this->lenPrivateKey] = '\0';
        this->publicKey[this->lenPublicKey] = '\0';

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

// TODO: Finish this function.
bool RSACrypter::setPrivateKey(char* privateKey, unsigned int sizeKey, string passphrase)
{
        BIO *pri = BIO_new_mem_buf(privateKey, sizeKey);
        if (pri == NULL) {
                printf("# Failed to generate memory BIO's for private and public keys!\n");
                ERR_load_crypto_strings();
                char* err;
                ERR_error_string(ERR_get_error(), err);
                printf("%s\n", err);
                return false;
        }

        this->keyPair = PEM_read_bio_RSAPrivateKey(pri, NULL, NULL, (void*)passphrase.c_str());
        if (this->keyPair == NULL) {

                if (ERR_get_error() == 101077092) {
                        printf("# Failed to load the private key! Wrong passphrase!\n\n");
                        return false;
                }

                printf("# Failed to read the BIO to our RSA keypair object! Error code: %ld\n");
                ERR_load_crypto_strings();
                char* err;
                ERR_error_string(ERR_get_error(), err);
                printf("%s\n", err);
                return false;
        }

        return true;
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
