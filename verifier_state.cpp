#include "verifier_state.h"
#include "constants.h"
#include <cryptopp/osrng.h>
#include <chrono>
#include <iostream> 
#include <thread>

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <iostream>
#include <sys/types.h>
#include <arpa/inet.h>

using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::microseconds;


void verifier_state(byte tape[PRNG_IN], 
                    byte **y, 
                    std::vector<Integer> *eps, 
                    byte commit_key[COMMIT_KEYLEN],
                    byte ***y_shares,
                    byte tape_commit[HMAC<SHA256>::DIGESTSIZE]) {
    

    if (DEBUG) std::cout << "Starting verifier state" << std::endl;
    /* Commit to random tape */
    HMAC<SHA256> hmac(commit_key, COMMIT_KEYLEN);
    hmac.Update(tape, PRNG_IN);
    byte verifier_commitment[HMAC<SHA256>::DIGESTSIZE];
    hmac.Final(verifier_commitment);

    /* Expand seed into pseudorandom values */
    OFB_Mode<AES>::Encryption prng;
    prng.SetKeyWithIV(tape, 32, tape+32, 16);

    /* Create epsilon vector */
    ModularArithmetic m = ModularArithmetic(Integer(NUM_PARTIES));
    for (unsigned int j=0; j<NUM_ITERATION; j++) {
        (*eps).push_back(m.RandomElement(prng));
    }

    /* Share public hashes */
    byte r[NUM_ITERATION][PRNG_IN];
    prng.GenerateBlock((byte *)r,NUM_ITERATION*PRNG_IN);
    if (DEBUG) std::cout << "Starting share_at" << std::endl;
    //for (unsigned int j=0; j<NUM_ITERATION; j++) {
    //
    auto table_thread_ftn = 
      [](unsigned int j, 
         byte **y,
         byte ***y_shares, 
         std::vector<Integer> *eps,
         byte r[NUM_ITERATION][PRNG_IN] ) {

        if (DEBUG) std::cout << "\tThread " << j << " start" << std::endl;
        share_at(y_shares[0][j],y[0],H_OUT,(*eps)[j],r[j]);
        for (unsigned int i=1; i<NUM_KEYS; i++) {
            for (unsigned int b = 0; b<H_OUT; b++) {
                y_shares[i][j][b] = y_shares[0][j][b] ^ y[0][b] ^ y[i][b];
            }
        }
        if (DEBUG) std::cout << "\tThread " << j << " end" << std::endl;
    };
    std::thread threads[NUM_ITERATION];
    for (unsigned int j=0; j<NUM_ITERATION; j++) {
        threads[j] = std::thread(table_thread_ftn, j, y, y_shares, eps, r);
    }
    for (unsigned int j=0; j<NUM_ITERATION; j++) {
        threads[j].join();
    }
    if (DEBUG) std::cout << "End share_at" << std::endl;

    /* Simulate Mixed Statement additional tables generation */
    if (MIXED_STATEMENT) {
        auto mixed_thread_ftn = 
          [](unsigned int j, 
             byte **y,
             byte ***y_shares, 
             std::vector<Integer> *eps,
             byte r[NUM_ITERATION][PRNG_IN] ) {
            for (unsigned int b = 0; b < 2; b++) {
                for (unsigned int i = 0; i < 8*H_OUT; i++) {
                    share_at(y_shares[0][j],y[0],1,(*eps)[j],r[j]);
                }
            }
        };
        for (unsigned int j=0; j<NUM_ITERATION; j++) {
            threads[j] = std::thread(table_thread_ftn, j, y, y_shares, eps, r);
        }
        for (unsigned int j=0; j<NUM_ITERATION; j++) {
            threads[j].join();
        }
    }
}

uint32_t run_verifier_state() {

    if (DEBUG) std::cout << "Starting common input allocation" << std::endl;
    //byte y[NUM_KEYS][H_OUT];
    byte **y  = (byte **)malloc(NUM_KEYS * sizeof(byte *));
    if(y == NULL) {
        std::cout << "Error allocating key structure" << std::endl;
        exit(1);
    }
    for (uint64_t i = 0; i < NUM_KEYS; i++) {
	y[i] = (byte *)malloc(H_OUT * sizeof(byte));
	if(y[i] == NULL) {
            std::cout << "Error allocating key " << i << std::endl;
            exit(1);
	}
    	OS_GenerateRandomBlock(false, y[i], H_OUT);
    }
    if (DEBUG) std::cout << "End common input allocation" << std::endl;

    std::vector<Integer> eps;

    if (DEBUG) std::cout << "Starting table allocation" << std::endl;
    //byte y_shares[NUM_KEYS][NUM_ITERATION][NUM_PARTIES*H_OUT];
    byte ***y_shares  = (byte ***)malloc(NUM_KEYS * sizeof(byte **));
    if(y_shares == NULL) {
        std::cout << "Error allocating key-shares structure" << std::endl;
        exit(1);
    }
    for (uint64_t i = 0; i < NUM_KEYS; i++) {
        y_shares[i] = (byte **)malloc(NUM_ITERATION * sizeof(byte *));
        if(y_shares[i] == NULL) {
            std::cout << "Error allocating key-shares structure[" << i << "]" << std::endl;
            exit(1);
        }
	    for (uint64_t j = 0; j < NUM_ITERATION; j++) {
                y_shares[i][j] = (byte *)malloc(NUM_PARTIES * H_OUT * sizeof(byte));
                if(y_shares[i][j] == NULL) {
                    std::cout << "Error allocating key-shares structure[" << i << "][" << j << "]" << std::endl;
                    exit(1);
                }
    
	    }
    }
    if (DEBUG) std::cout << "Ending table allocation" << std::endl;

    auto time_pre_verifier = high_resolution_clock::now();

    byte tape[PRNG_IN];//Set to true to generate random values (running out of entropy!)
    OS_GenerateRandomBlock(false, tape, PRNG_IN); //step 1 Fig6: generating seed

    byte commit_key[COMMIT_KEYLEN]; //Server: send commit_key
    OS_GenerateRandomBlock(false, commit_key, COMMIT_KEYLEN); //step 1 Fig6: generating keys
    //Client: send view commitments?
    byte tape_commit[HMAC<SHA256>::DIGESTSIZE]; //steps 1 Fig6: allocate space for C_s
    //Server: send tape_commit
    if (DEBUG) std::cout << "Finished sampling randomness" << std::endl;

    verifier_state(tape, y, &eps, commit_key, y_shares, tape_commit); //step 2-4 Fig6: generates 2D table

    auto time_post_verifier = high_resolution_clock::now();
    auto time_verifier_us = duration_cast<microseconds>(time_post_verifier - time_pre_verifier).count();
    std::cout << "MPCitH encoding time (Verifier and Prover): " << time_verifier_us / 1000 <<  " ms" << std::endl;
    return time_verifier_us;
}
