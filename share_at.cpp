#include <cryptopp/modarith.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include "constants.h"

using namespace CryptoPP;
using CryptoPP::byte;

/* Share input bits into output_shares (concatenated vector) */
void share_at(byte *output_shares, byte *input, size_t input_len, Integer K, byte *r) {
    long k = K.ConvertToLong(); /* convert so we can do index operations */ 
    /* Seed PRG */
    OFB_Mode<AES>::Encryption prng;
    prng.SetKeyWithIV(r, 32, r+32, 16);  
    /* Sample from PRG */
    prng.GenerateBlock(output_shares, NUM_PARTIES*input_len);
    /* apply correction to X^(k) */
    for (unsigned int b = 0; b < input_len; b++) {
        for (unsigned int v = 0; v < NUM_PARTIES; v++) {
            *(output_shares+input_len*k+b) ^= *(output_shares+input_len*v+b);
        }
        *(output_shares+input_len*k+b) ^= *(input+b);
    }
}

