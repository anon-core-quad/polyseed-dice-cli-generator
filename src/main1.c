/*
 * Copyright 2021 tevador <tevador@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <polyseed.h>

#include <sodium/core.h>
#include <sodium/utils.h>
#include <sodium/randombytes.h>
#include <utf8proc.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <assert.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <ctype.h>

#include "pbkdf2.h"

#define MIN(a,b) ((a)>(b)?(b):(a))

static size_t utf8_nfc(const char* str, polyseed_str norm) {
    utf8proc_uint8_t* s = utf8proc_NFC((const utf8proc_uint8_t*)str);
    size_t len = strlen((const char*)s);
    size_t size = MIN(len, (size_t)POLYSEED_STR_SIZE - 1);
    memcpy(norm, s, size);
    norm[size] = '\0';
    sodium_memzero(s, len);
    free(s);
    return size;
}

static size_t utf8_nfkd(const char* str, polyseed_str norm) {
    utf8proc_uint8_t* s = utf8proc_NFKD((const utf8proc_uint8_t*)str);
    size_t len = strlen((const char*)s);
    size_t size = MIN(len, (size_t)POLYSEED_STR_SIZE - 1);
    memcpy(norm, s, size);
    norm[size] = '\0';
    sodium_memzero(s, len);
    free(s);
    return size;
}

// Static array of bytes for testing
// static const char diceRolls[] = {
//     0xdd, 0x76, 0xe7, 0x35, 0x9a, 0x0d, 0xed, 0x37,
//     0xcd, 0x0f, 0xf0, 0xf3, 0xc8, 0x29, 0xa5, 0xae,
//     0x01, 0x67, 0xf3,
// };

const size_t POLYSEED_RANDBYTES = 19;
const size_t DICE_ROLLS = 2; //TODO set to 99
//const char diceRolls[] = "152415341253412341524312543124312543612435124561243512431524312534";
const char* diceRolls = {};
char *entropy;
const char* password = NULL;

void concat(const char *s1, const char *s2) {
    //entropy = malloc(strlen(s1) + strlen(s2) + 1);
    //if (!entropy) return NULL;
    strcpy(entropy, s1);
    strcat(entropy, s2);
    //return r;  // caller must free()
}

// Convert 32 bytes → 64-char hex string
void print_hash(const char *digest, unsigned int mdlen) {
    printf("Entropy Hash SHA256 (Hex): ");
    for (unsigned int i = 0; i < mdlen; i++) {
        // Print each byte as a 2-digit hex number
        printf("%02x", digest[i]);
    }
    printf("\n");
}

#define DEBUG 0
int DECODE_MNEMONIC_TEST = 0;

static void gen_rand_bytes(void* result, size_t n) {

    // Generate 19 bytes of entropy from internal RNG function
    char randomRNG[n] = {};
    randombytes_buf(&randomRNG, n);

    entropy = malloc(n + DICE_ROLLS + 1);

    if (DEBUG == 1) {
        printf("Random RNG size: %lu\n", sizeof(randomRNG));
        printf("Dice rolls size: %lu\n", sizeof(diceRolls));
        printf("%s\n", randomRNG);
        printf("%s\n", diceRolls);
    }

    concat(diceRolls, randomRNG);

    if (DEBUG == 1) {
        printf("Entropy RNG + Dices total size: %lu\n", sizeof(entropy));
        printf("%s\n", entropy);
    }

    char digest[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;

    if (EVP_Digest(entropy, strlen((const char *)entropy), (unsigned char*)digest, &mdlen, EVP_sha256(), NULL)!= 1) {
        exit(EXIT_FAILURE);
    }

    if (DEBUG == 1) {
        print_hash(digest, mdlen);
    }

    memcpy(result, digest, n);
}

static void polyseed_init() {
    polyseed_dependency pd = {
        .randbytes = &gen_rand_bytes,
        .pbkdf2_sha256 = &crypto_pbkdf2_sha256,
        .memzero = &sodium_memzero,
        .u8_nfc = &utf8_nfc,
        .u8_nfkd = &utf8_nfkd,
        .time = NULL,
        .alloc = NULL,
        .free = NULL,
    };
    polyseed_inject(&pd);
}

static const polyseed_lang* get_lang_by_name(const char* name) {
    for (int i = 0; i < polyseed_get_num_langs(); ++i) {
        const polyseed_lang* lang = polyseed_get_lang(i);
        if (0 == strcmp(name, polyseed_get_lang_name_en(lang))) {
            return lang;
        }
        if (0 == strcmp(name, polyseed_get_lang_name(lang))) {
            return lang;
        }
    }
    return NULL;
}

#define FEATURE_FOO 1
#define FEATURE_BAR 2
#define FEATURE_QUX 4

int start_menu(int argc, char* argv[]) {

    int opt;
    int dice_faces = 6;
    int dice_rolls = DICE_ROLLS;
    diceRolls = "";
    int status = EXIT_SUCCESS;

    while ((opt = getopt(argc, argv, ":hf:d:p:d")) != -1) {
        switch (opt) {

            case 'h':
            printf("\n");
                printf("-h  Show this help menu\n");

                printf("-d  Insert dice values\n");
                printf("\t\tvalues: insert a consecutive values of dice results until reach the setted limit\n");
                printf("\t\t%d is the default and reccomended value of rolls for a standard dice (D6)\n",dice_rolls);

                printf("-f Insert number of faces\n");
                printf("\t\t2 is the value for a coin, 6 for a standard dice, but you can insert the type of dice you prefer\n");

                printf("-p Insert password for seed encryption\n");

                printf("-e Test the inverse process, decode the seed\n");

                printf("Usage example: %s -d 565612356125312536123514263451235612\n", argv[0]);

                status = EXIT_FAILURE;
                break;

            case 'f':
                dice_faces = (int)strtol(optarg, NULL, 10);
                break;

            case 'p':
                password = optarg;
                break;

            case 'e':
                DECODE_MNEMONIC_TEST = 1;
                break;

            case 'd':
                diceRolls = optarg;
                if (strlen(diceRolls) < dice_rolls && dice_faces == 6) {
                    printf("Insert at least a sequence of %d values after -d param\n", dice_rolls);
                    status = EXIT_FAILURE;
                    break;
                }

                break;
                
            default:
                fprintf(stderr, "Usage: %s -d values [-f faces]\n", argv[0]);
                printf("Usage example: %s -d 565612356125312536123514263451235612 -f 6\n", argv[0]);
                printf("Usage example: %s -d 4152354661243333141667\n", argv[0]);
                status = EXIT_FAILURE;
                break;
        }
    }

    printf("Dices faces: %d\n", dice_faces);
    printf("Dices rolls: %d\n", (int)strlen(diceRolls));
    printf("Dices values: %s\n", diceRolls);

    for (int i = optind; i < argc; i++) {
        printf("input: %s\n", argv[i]);
    }

    if (diceRolls == NULL) {
        fprintf(stderr, "Error: option -d is mandatory\n");
    }

    return status;
}

int main(int argc, char* argv[]) {

    if (sodium_init() == -1) {
        printf("sodium_init failed\n");
        return 1;
    }

    if (start_menu(argc, argv) == 1) {
        return 1;
    }

    polyseed_init();

    polyseed_enable_features(FEATURE_FOO | FEATURE_BAR);

    polyseed_status result;
    polyseed_data* seed1;

    //create a new seed
    printf("Generating new seed...\n");
    result = polyseed_create(argc > 1 ? FEATURE_FOO : 0, &seed1);
    if (result != POLYSEED_OK) {
        printf("ERROR: %i\n", result);
        return 1;
    }

    //generate a key from the seed
    uint8_t key1[32];
    polyseed_keygen(seed1, POLYSEED_MONERO, sizeof(key1), key1);
    printf("Private key: ");
    for (unsigned i = 0; i < sizeof(key1); ++i)
		printf("%02x", key1[i] & 0xff);
    printf("\n");

    if (password != NULL) {
        //protect the seed with a password
        printf("Encrypting with password '%s' ...\n", password);
        polyseed_crypt(seed1, password);
    }

    //encode into a mnemonic phrase
    polyseed_str phrase;
    polyseed_encode(seed1, get_lang_by_name("English"), POLYSEED_MONERO, phrase);
    printf("Mnemonic: %s\n", phrase);

    polyseed_free(seed1);

    if (DECODE_MNEMONIC_TEST == 1) {
        printf("-------------------------------------------------\n");

        //decode a seed from the phrase
        printf("Decoding mnemonic phrase for testing reasons...\n");

        polyseed_data* seed2;
        const polyseed_lang* lang;
        result = polyseed_decode(phrase, POLYSEED_MONERO, &lang, &seed2);
        if (result != POLYSEED_OK) {
            printf("ERROR: %i\n", result);
            return 1;
        }
        printf("Detected language: %s\n", polyseed_get_lang_name_en(lang));

        printf("Encrypted: %s\n", polyseed_is_encrypted(seed2) ? "true" : "false");

        if (polyseed_get_feature(seed2, FEATURE_FOO)) {
            printf("Seed has the 'Foo' feature\n");
        }

        //decrypt
        if (polyseed_is_encrypted(seed2)) {
            printf("Decrypting with password '%s' ...\n", password);
            polyseed_crypt(seed2, password);
        }

        //recover the key
        uint8_t key2[32];
        polyseed_keygen(seed2, POLYSEED_MONERO, sizeof(key2), key2);
        printf("Private key: ");
        for (unsigned i = 0; i < sizeof(key2); ++i)
            printf("%02x", key2[i] & 0xff);
        printf("\n");

        polyseed_free(seed2);
    }
}
