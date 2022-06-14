/* Given public inputs + verifiers initial random seed, 
 * compute/recompute verifier's internal state up until F_COT
 */
#ifndef VERIFIER_STATE_H
#define VERIFIER_STATE_H
#include "share_at.h"
#include "constants.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

uint32_t run_verifier_state();


void verifier_state(CryptoPP::byte tape[PRNG_IN], 
                    CryptoPP::byte **y, 
                    std::vector<Integer> *eps, 
     	            CryptoPP::byte commit_key[COMMIT_KEYLEN],
                    CryptoPP::byte ***y_shares,
                    CryptoPP::byte tape_commit[HMAC<SHA256>::DIGESTSIZE]);

#endif
