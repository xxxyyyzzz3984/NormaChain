#ifndef ECIES_H
#define ECIES_H

#include <iostream>
#include <string>
#include <stdlib.h>
#include <inttypes.h>
#include <boost/serialization/vector.hpp>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

#include <ctime>

#define ECIES_CURVE  NID_secp521r1
#define ECIES_CIPHER EVP_aes_256_cbc()
#define ECIES_HASHER EVP_sha512()

typedef struct {
    struct {
        uint64_t key;
        uint64_t mac;
        uint64_t orig;
        uint64_t body;
    } length;

} secure_head_t;

class cryptex4transmit {
public:
    std::vector<char> cryptex_body_vec;
    std::vector<char> cryptex_key_vec;
    uint64_t body_len;
    uint64_t key_len;
    void convert_cryptex2transmit(char* cryptex);
    template<class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar & cryptex_body_vec;
        ar & cryptex_key_vec;
        ar & body_len;
        ar & key_len;
    }
};

EC_KEY * ecies_key_create();
EC_GROUP * ecies_group();
char * ecies_key_public_get_hex(EC_KEY *key);
char * ecies_key_private_get_hex(EC_KEY *key);
char * ecies_encrypt(char *key, unsigned char *data, size_t length);
unsigned char * ecies_decrypt(char *key, char *cryptex, size_t *length);
unsigned char * ecies_decrypt(char *key, char *cryptex, size_t *length);
unsigned char * ecies_decrypt_by_parts(char *key, unsigned char *crypt_key_data, int crypt_key_len, unsigned char *crypt_body_data, int crypt_body_len);
EC_KEY * ecies_key_create_public_hex(char *hex);
EC_KEY * ecies_key_create_private_hex(char *hex);
void * ecies_key_derivation(const void *input, size_t ilen, void *output, size_t *olen);
EC_KEY * ecies_key_create_public_octets(unsigned char *octets, size_t length);

char * secure_alloc(uint64_t key, uint64_t mac, uint64_t orig, uint64_t body);
unsigned char * secure_key_data(char *cryptex);
void secure_free(char *cryptex);
unsigned char * secure_body_data(char *cryptex);
uint64_t secure_body_length(char *cryptex);
unsigned char * secure_mac_data(char *cryptex);
uint64_t secure_mac_length(char *cryptex);
uint64_t secure_key_length(char *cryptex);
uint64_t secure_orig_length(char *cryptex);
unsigned char * secure_orig_data(char *cryptex);

void ecies_example();

#endif
