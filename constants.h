/* Configure several constant parameters for prover & verifier */
#ifndef CONSTANTS_H
#define CONSTANTS_H

/* Enable verbose debug printing */
#define DEBUG 0

/* Run mixed-statement proof? */
#define MIXED_STATEMENT 1

/* Number of public key hashes in the disjunction */
#define LOG_NUM_KEYS 20
#define NUM_KEYS (1 << LOG_NUM_KEYS)

/* Number of parties in the MPCitH proof */
#define NUM_PARTIES 3

/* Number of iterations required to achieve soundness
 * (computed based on NUM_PARTIES) */
#define NUM_ITERATION 25

/* Size of Hash output (in bytes) */
#define H_OUT 32
/* Size of public keys (in bytes) */
#define H_IN  32

/* PRNG input length (in bytes) */
#define PRNG_IN 64

/* Commitment security parameter (key length in bytes)*/
#define COMMIT_KEYLEN 16


#endif
