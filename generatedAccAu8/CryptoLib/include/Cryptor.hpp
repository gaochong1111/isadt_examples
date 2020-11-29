#ifndef Cryptor_hpp
#define Cryptor_hpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

class Cryptor
{
private:
    /* data */
public:
    int aes_encrypt(char* in, char* key, char* out);//1
    int aes_decrypt(char* in, char* key, char* out);//2
    int rsa_pubkey_encrypt(char* in, char* pubkey, char* out);//3
    int rsa_prikey_decrypt(char* in, char* prikey, char* out);//4
    int sha1_decrypt(char* in, char* pubkey, char* out);//5
    int sha1_encrypt(char* in, char* prikey, char* out);//6
    int des_cbc_encrypt(char* in, char* key, char* out);//7
    int des_cbc_decrypt(char* in, char* key, char* out);//8
    int sha256(char* in, int length, char* out);//9
    int md5(char* in, char* key, char* out);//10
    int crypt(char*in, char* key, int length, char* out, int mod);
    Cryptor(/* args */);
    ~Cryptor();
};


#endif