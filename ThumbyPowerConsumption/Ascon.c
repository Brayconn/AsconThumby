#include "Ascon.h"
#include <assert.h>
#include <string.h>

//When defined, uses memcpy and byte-by-byte operations instead of relying on 64 bit integers
//Fixes crashes on devices that are strict about memory alignment
//#define FIX_ALIGNMENT_CRASHES

//When defined, prints a bunch of debug info about different parts of the algorithm
//Make sure that print(char const*)
//  and printbytes(char const*, unsigned char const*, uint64_t)
//  are defined somewhere in your project (such as in AsconTests.cpp)
//#define ASCON_PRINT_STATE

//When defined, uses a lookup table for the S-BOX instead of actually calculating everything
#define SBOX_LOOKUP

static void Ascon_Pad_To_State(uint8_t* source, uint8_t len, uint64_t* state)
{
  assert(len < 16);
  uint8_t* stateBytes = (uint8_t*)state;
  size_t i;
  for(i = 0; i < len; i++)
    stateBytes[i] ^= source[i];
  stateBytes[i] ^= 0x01;
}

/// <summary>
/// Sourced from Table 5
/// </summary>
uint64_t Ascon_Const[] =
{
  0x000000000000003c,
  0x000000000000002d,
  0x000000000000001e,
  0x000000000000000f,
  0x00000000000000f0,
  0x00000000000000e1,
  0x00000000000000d2,
  0x00000000000000c3,
  0x00000000000000b4,
  0x00000000000000a5,
  0x0000000000000096,
  0x0000000000000087,
  0x0000000000000078,
  0x0000000000000069,
  0x000000000000005a,
  0x000000000000004b
};

static void Ascon_pConstant_Addition(uint64_t* state, uint8_t rnd, uint8_t i)
{
  assert(1 <= rnd && rnd <= 16);
  assert(0 <= i && i < rnd);
  size_t index = 16 - rnd + i;
  assert(0 <= index && index <= 15);
  state[2] ^= Ascon_Const[index];
}

/// <summary>
/// Sourced from Table 6
/// </summary>
#ifdef SBOX_LOOKUP
static uint8_t Ascon_S_Box[] =
{
  0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02, 0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
  0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18, 0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17
};
#endif

static void Ascon_pSubstitution(uint64_t* state)
{
#ifdef SBOX_LOOKUP
  uint8_t data = 0;
  for(size_t j = 0; j < 64; j++)
  {
    data = ((state[4] >> j) & 1)
         | (((state[3] >> j) & 1) << 1)
         | (((state[2] >> j) & 1) << 2)
         | (((state[1] >> j) & 1) << 3)
         | (((state[0] >> j) & 1) << 4);
    assert(data < sizeof(Ascon_S_Box));

    data = Ascon_S_Box[data];
    assert(data < sizeof(Ascon_S_Box));

    uint64_t unset = ~((uint64_t)1 << j);
    state[4] = (state[4] & unset) | ((uint64_t)((data     ) & 1) << j);
    state[3] = (state[3] & unset) | ((uint64_t)((data >> 1) & 1) << j);
    state[2] = (state[2] & unset) | ((uint64_t)((data >> 2) & 1) << j);
    state[1] = (state[1] & unset) | ((uint64_t)((data >> 3) & 1) << j);
    state[0] = (state[0] & unset) | ((uint64_t)((data >> 4) & 1) << j);
  }
#else
  //adapted from the reference code
  state[0] ^= state[4];
  state[4] ^= state[3];
  state[2] ^= state[1];
  uint64_t s0 = state[0] ^ (~state[1] & state[2]);
  uint64_t s1 = state[1] ^ (~state[2] & state[3]);
  uint64_t s2 = state[2] ^ (~state[3] & state[4]);
  uint64_t s3 = state[3] ^ (~state[4] & state[0]);
  uint64_t s4 = state[4] ^ (~state[0] & state[1]);
  s1 ^= s0;
  s0 ^= s4;
  s3 ^= s2;
  s2 = ~s2;
  state[0] = s0;
  state[1] = s1;
  state[2] = s2;
  state[3] = s3;
  state[4] = s4;
#endif
#ifdef ASCON_PRINT_STATE
  printbytes(" substitution layer", state, 5 * sizeof(uint64_t));
#endif
}

static inline uint64_t Ascon_RotateRight(uint64_t value, uint8_t amount)
{
  return (value << (64 - amount)) | (value >> amount);
}

static void Ascon_pLinear_Diffusion(uint64_t* state)
{
  state[0] ^= Ascon_RotateRight(state[0], 19) ^ Ascon_RotateRight(state[0], 28);
  state[1] ^= Ascon_RotateRight(state[1], 61) ^ Ascon_RotateRight(state[1], 39);
  state[2] ^= Ascon_RotateRight(state[2],  1) ^ Ascon_RotateRight(state[2],  6);
  state[3] ^= Ascon_RotateRight(state[3], 10) ^ Ascon_RotateRight(state[3], 17);
  state[4] ^= Ascon_RotateRight(state[4],  7) ^ Ascon_RotateRight(state[4], 41);
}

static void Ascon_p(uint64_t* state, uint8_t rnd)
{
  for(uint8_t i = 0; i < rnd; i++)
  {
    Ascon_pConstant_Addition(state, rnd, i);
    Ascon_pSubstitution(state);
    Ascon_pLinear_Diffusion(state);
#ifdef ASCON_PRINT_STATE
    printbytes(" round output", state, 5 * sizeof(uint64_t));
#endif
  }
}

static void Ascon_AEAD128_Shared(uint64_t* key, uint64_t* nonce, uint8_t* associated, size_t associatedLength, uint64_t* state)
{
  //Initialization
  uint64_t iv = 0x00001000808c0001;
  state[0] = iv;
  state[1] = key[0];
  state[2] = key[1];
  state[3] = nonce[0];
  state[4] = nonce[1];

#ifdef ASCON_PRINT_STATE
  printbytes("init 1st key xor", state, 5*sizeof(uint64_t));
#endif

  Ascon_p(state, 12);
  state[3] ^= key[0];
  state[4] ^= key[1];

#ifdef ASCON_PRINT_STATE
  printbytes("init 2nd key xor", state, 5 * sizeof(uint64_t));
#endif

  //Processing associated data
  if(associatedLength > 0)
  {
    size_t i;
    for(i = 0; associatedLength - i >= 16; i += 16)
    {
      state[0] ^= *((uint64_t*)(&associated[i  ]));
      state[1] ^= *((uint64_t*)(&associated[i+8]));
#ifdef ASCON_PRINT_STATE
      printbytes("absorb adata", state, 5 * sizeof(uint64_t));
#endif
      Ascon_p(state, 8);
    }
    Ascon_Pad_To_State(&associated[i], associatedLength - i, state);
#ifdef ASCON_PRINT_STATE
    printbytes("pad adata", state, 5 * sizeof(uint64_t));
#endif
    Ascon_p(state, 8);
  }
  state[4] ^= 0x8000000000000000;
}

void Ascon_AEAD128_Encode(uint64_t* key, uint64_t* nonce, uint8_t* associated, size_t associatedLength, uint8_t* plaintext, size_t plaintextLength, uint8_t* ciphertext, uint64_t* tag)
{
#ifdef ASCON_PRINT_STATE
    print("encrypt");
    printbytes("k", key,   2 * sizeof(uint64_t));
    printbytes("n", nonce, 2 * sizeof(uint64_t));
    printbytes("a", associated, associatedLength);
    printbytes("m", plaintext, plaintextLength);
#endif

  uint64_t state[5];
  Ascon_AEAD128_Shared(key, nonce, associated, associatedLength, state);

  //Processing plaintext
  size_t i;
  for(i = 0; plaintextLength - i >= 16; i += 16)
  {
    state[0] ^= *(uint64_t*)(plaintext + i    );
    state[1] ^= *(uint64_t*)(plaintext + i + 8);
    
    #ifndef FIX_ALIGNMENT_CRASHES
    *(uint64_t*)(ciphertext + i    ) = state[0];
    *(uint64_t*)(ciphertext + i + 8) = state[1];
    #else
    memcpy(ciphertext + i, state, 16);
    #endif
    
    Ascon_p(state, 8);
  }
  assert(i % 16 == 0);
  Ascon_Pad_To_State(&plaintext[i], plaintextLength - i, state);
  for(; i < plaintextLength; i++)
    ciphertext[i] = ((uint8_t*)state)[i%16];
  

  //Finalization
  state[2] ^= key[0];
  state[3] ^= key[1];
  Ascon_p(state, 12);

  tag[0] = (state[3] ^ key[0]);
  tag[1] = (state[4] ^ key[1]);
}

bool Ascon_AEAD128_Decode(uint64_t* key, uint64_t* nonce, uint8_t* associated, size_t associatedLength, uint8_t* ciphertext, size_t ciphertextLength, uint8_t* plaintext, uint64_t* tag)
{
  uint64_t state[5];
  Ascon_AEAD128_Shared(key, nonce, associated, associatedLength, state);

  //Processing ciphertext
  size_t i;
  uint8_t* stateBytes = (uint8_t*)state;
  for(i = 0; ciphertextLength - i >= 16; i += 16)
  {
    #ifndef FIX_ALIGNMENT_CRASHES
    uint64_t c1 = *(uint64_t*)(ciphertext + i    );
    uint64_t c2 = *(uint64_t*)(ciphertext + i + 8);
    *(uint64_t*)(plaintext + i    ) = (state[0] ^ c1);
    *(uint64_t*)(plaintext + i + 8) = (state[1] ^ c2);
    #else
    for(size_t j = 0; j < 16; j++)
      plaintext[i+j] = (stateBytes[j] ^ ciphertext[i+j]);
    #endif
    
    #ifndef FIX_ALIGNMENT_CRASHES
    state[0] = c1;
    state[1] = c2;
    #else
    memcpy(state, ciphertext + i, 16);
    #endif
    
    Ascon_p(state, 8);
  }
  assert(i % 16 == 0);
  for (; i < ciphertextLength; i++)
  {
    plaintext[i] = stateBytes[i % 16] ^ ciphertext[i];
    stateBytes[i % 16] = ciphertext[i];
  }
  stateBytes[i % 16] ^= 0x01;

  //Finalization
  state[2] ^= key[0];
  state[3] ^= key[1];
  Ascon_p(state, 12);

  uint64_t t1 = (state[3] ^ key[0]);
  uint64_t t2 = (state[4] ^ key[1]);
  return (t1 == tag[0]) & (t2 == tag[1]);
}
