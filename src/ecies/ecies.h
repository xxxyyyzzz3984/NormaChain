#ifndef ECIES_H
#define ECIES_H

#include <iostream>
#include <string>
#include <stdlib.h>
#include <inttypes.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>

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

EC_KEY * ecies_key_create();
EC_GROUP * ecies_group();
char * ecies_key_public_get_hex(EC_KEY *key);
char * ecies_key_private_get_hex(EC_KEY *key);
char * ecies_encrypt(char *key, unsigned char *data, size_t length);
unsigned char * ecies_decrypt(char *key, char *cryptex, size_t *length);
unsigned char * ecies_decrypt(char *key, char *cryptex, size_t *length);
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

void example();

#endif
