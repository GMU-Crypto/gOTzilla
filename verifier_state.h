/* Given public inputs + verifiers initial random seed, 
 * compute/recompute verifier's internal state up until F_COT
 */
#ifndef VERIFIER_STATE_H
#define VERIFIER_STATE_H
#include "share_at.h"
#include "constants.h"
#include <cryptlib.h>
#include <modes.h>
#include <aes.h>
#include <hmac.h>
#include <sha.h>

void run_verifier_state();

void run_verifier_state_network();

void verifier_state(CryptoPP::byte tape[PRNG_IN], 
                    CryptoPP::byte **y, 
                    std::vector<Integer> *eps, 
     	            CryptoPP::byte commit_key[COMMIT_KEYLEN],
                    CryptoPP::byte ***y_shares,
                    CryptoPP::byte tape_commit[HMAC<SHA256>::DIGESTSIZE]);

void verifier_state_network(CryptoPP::byte tape[PRNG_IN], 
                    CryptoPP::byte **y, 
                    std::vector<Integer> *eps, 
     	            CryptoPP::byte commit_key[COMMIT_KEYLEN],
                    CryptoPP::byte ***y_shares,
                    CryptoPP::byte tape_commit[HMAC<SHA256>::DIGESTSIZE]);

#endif
