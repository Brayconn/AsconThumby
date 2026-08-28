#include <assert.h>
#include <cstdio>
#include <cstring>

//When defined, prints a bunch of debug info about different parts of the algorithm
//Make sure to define it in Ascon.c too!
//#define ASCON_PRINT_STATE

#include "..\Ascon.h"
#include "ref\aead.c"

#ifdef ASCON_PRINT_STATE
void print(char const* message)
{
	printf("%s\n", message);
}
void printbytes(char const* message, unsigned char const* data, uint64_t length)
{
	printf("%s\n", message);
	for (size_t i = 0; i < length; i++)
		printf("%02X ", data[i]);
	printf("\n");
}
void printword(const char* text, const uint64_t x)
{
	printf("%s\n", text);
	printf("%ld\n", x);
}
void printstate(char const* message, struct ascon_state_t const* state)
{
	printbytes(message, (uint8_t*)state, 5*sizeof(uint64_t));
}
#endif

bool TestRoundTrip(const char* message, const char* associated)
{
	//setup
	int messageLen = (message != nullptr) ? strlen(message) : 0;
	if(messageLen > 0)
		printf("Message Len %d:\n\t%s\n", messageLen, message);
	
	int associatedLen = (associated != nullptr) ? strlen(associated) : 0;
	if(associatedLen > 0)
		printf("Associated Len %d:\n\t%s\n", associatedLen, associated);

	uint8_t* actualCiphertext = new uint8_t[messageLen]();
	uint64_t actualTag[2] = { 0,0 };
	char* actualPlaintext = new char[messageLen + 1]();

	uint8_t* expectedCiphertext = new uint8_t[messageLen + sizeof(actualTag)]();
	uint64_t* expectedCiphertextTag = (uint64_t*)(expectedCiphertext + messageLen);
	char* expectedPlaintext = new char[messageLen]();
	
	//hardcoded key and nonce are probably fine for a test
	uint64_t key[2] = { 0x00D00D0BA17ED000, 0x00F00D0A7ED02025 };
	uint64_t nonce[2] = { 7, 37645 };

	//encode
	uint64_t expectedLen = 0;
	crypto_aead_encrypt(expectedCiphertext, &expectedLen,
		(uint8_t*)message, messageLen,
		(uint8_t*)associated, associatedLen,
		nullptr, (uint8_t*)nonce,
		(uint8_t*)key);
	assert(expectedLen == messageLen + sizeof(actualTag));
	
	Ascon_AEAD128_Encode(key, nonce,
		(uint8_t*)associated, associatedLen,
		(uint8_t*)message, messageLen,
		(uint8_t*)actualCiphertext, actualTag);

	assert(memcmp(expectedCiphertext, actualCiphertext, messageLen) == 0);
	assert(memcmp(expectedCiphertextTag, actualTag, sizeof(actualTag)) == 0);

	//decode
	int expectedOk = crypto_aead_decrypt((uint8_t*)expectedPlaintext, &expectedLen,
		nullptr,
		(uint8_t*)expectedCiphertext, messageLen + sizeof(actualTag),
		(uint8_t*)associated, associatedLen,
		(uint8_t*)nonce, (uint8_t*)key);
	assert(expectedLen == messageLen);

	bool actualOk = Ascon_AEAD128_Decode(key, nonce,
		(uint8_t*)associated, associatedLen,
		(uint8_t*)actualCiphertext, messageLen,
		(uint8_t*)actualPlaintext, actualTag);
	
	assert((expectedOk == 0) == actualOk);
	assert(memcmp(expectedPlaintext, actualPlaintext, messageLen) == 0);
		
	delete[] actualCiphertext;
	delete[] actualPlaintext;
	delete[] expectedCiphertext;
	delete[] expectedPlaintext;

	return actualOk;
}


const int messageCount = 13;
const char* messages[messageCount] =
{
	nullptr,
	"",
	"Hello, ",
	"World!",
	"Hello, World!",
	"0123456789ABCDEF",
	"0123456789ABCDEFG",
	"0123456789ABCDEFGHIJKLM",
	"0123456789ABCDEFGHIJKLMN",
	"0123456789ABCDEFGHIJKLMNO",
	"0123456789ABCDEFGHIJKLMNOPWRSTU",
	"0123456789ABCDEF0123456789ABCDEF",
	"0123456789ABCDEF0123456789ABCDEFG"
};

//Tests that the example from here works
//https://infsec.de/wp-content/uploads/grafik-217-1024x493.png
void TestKnown()
{
	const char plaintext[] = "This is a simple test";
	assert(sizeof(plaintext) - 1 == 21);
	uint64_t key[2] = { 0x74657374, 0 }; //"test"
	uint64_t nonce[2] = { 0xFF,0 };
	const char associated[] = "test";
	assert(sizeof(associated) - 1 == 4);

	/*
	uint8_t ciphertext[sizeof(plaintext) - 1] = { 0 };
	uint64_t tag[2] = { 0,0 };
	Ascon_AEAD128_Encode(key, nonce,
		(uint8_t*)associated, sizeof(associated) - 1,
		(uint8_t*)plaintext, sizeof(plaintext) - 1,
		ciphertext, tag);
	/*/
	uint8_t ciphertext[sizeof(plaintext) - 1 + 2 * sizeof(uint64_t)] = { 0 };
	uint64_t* tag = (uint64_t*)(ciphertext + sizeof(plaintext) - 1);
	uint64_t ciphertextLen = sizeof(ciphertext);
	crypto_aead_encrypt(ciphertext, &ciphertextLen,
		(uint8_t*)plaintext, sizeof(plaintext) - 1,
		(uint8_t*)associated, sizeof(associated) - 1,
		nullptr, (uint8_t*)nonce,
		(uint8_t*)key);
	//*/


	uint64_t expected_tag[2] = { 0xD2E7C2E089E5BE52, 0xFF7F7F12F6547ED1 };
	assert(tag[0] == expected_tag[0] && tag[1] == expected_tag[1]);

	uint8_t expected_ciphertext[sizeof(plaintext) - 1] =
	{ 
		0x4C, 0xA5, 0xDF, 0x73, 0x67, //this
		0xC3, 0x05, 0x45, //is
		0x37, 0x5C, //a
		0xF9, 0x2F, 0xCE, 0xB1, 0x5E, 0x5A, 0x63, //simple
		0xE7, 0x20, 0xD5, 0x1D //test
	};

	assert(sizeof(ciphertext) == sizeof(expected_ciphertext));
	for (size_t i = 0; i < sizeof(ciphertext); i++)
	{
		//assert(ciphertext[i] == expected_ciphertext[i]);
	}
}

int main()
{
	//TestKnown();

	for (int i = 0; i < messageCount; i++)
	{
		for (int j = 0; j < messageCount; j++)
		{
			bool ok = TestRoundTrip(messages[i], messages[j]);
			assert(ok);
		}
	}
}