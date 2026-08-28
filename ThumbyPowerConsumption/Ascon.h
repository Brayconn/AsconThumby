#ifndef ASCON
#define ASCON

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif

#ifdef ASCON_PRINT_STATE
extern void print(const char* text);
extern void printbytes(const char* text, const uint8_t* b, uint64_t len);
extern void printword(const char* text, const uint64_t x);
#endif

void Ascon_AEAD128_Encode(uint64_t* key, uint64_t* nonce, uint8_t* associated, size_t associatedLength, uint8_t* plaintext, size_t plaintextLength, uint8_t* ciphertext, uint64_t* tag);
bool Ascon_AEAD128_Decode(uint64_t* key, uint64_t* nonce, uint8_t* associated, size_t associatedLength, uint8_t* ciphertext, size_t ciphertextLength, uint8_t* plaintext, uint64_t* tag);

#ifdef __cplusplus
}
#endif

#endif