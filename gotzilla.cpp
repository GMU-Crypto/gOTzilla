
#include <cstddef>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <cstdint>

#include "seal/seal.h"
#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"

#include "emp-tool/utils/aes.h"
#include "emp-tool/utils/prg.h"

#include "polynomial.hpp"

#include "good_index.h"
#include "verifier_state.h"
#include "constants.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include<strings.h>
#include<iostream>
#include<sys/types.h>
#include <arpa/inet.h>


using std::cout;
using std::endl;
using namespace seal;
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::microseconds;
using namespace std::this_thread;     // sleep_for, sleep_until
using namespace std::chrono_literals; // ns, us, ms, s, h, etc.
using std::chrono::system_clock;

inline unsigned int to_uint(char ch)
{
    return static_cast<unsigned int>(static_cast<unsigned char>(ch));
}

std::string gen_random(const int len) {
    static const char alphanum[] =
        "0123456789"
        "abcdef";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    
    return tmp_s;
}


uint32_t oneofnot();

int main()
{
    cout << "Number of elements: 2^" << LOG_NUM_KEYS << endl;

    //Steps 1-4 of main protocol
    uint32_t a,b,c;
    a = run_verifier_state();  

    //Steps 5-6: 1-out-of-n OT construction based on PIR
    //includes polynomial interpolation part from Pi_well-formed
    b = oneofnot();

    //Bounded noise proof from Pi_well-formed
    c = run_good_index(0);

    cout << "Total: " << (a + b + c)/1000 << endl;
    return 0;
}

uint32_t oneofnot() {

    uint64_t number_of_items = NUM_KEYS;
    uint64_t size_per_item = (NUM_PARTIES-1)*256*NUM_ITERATION/8; // in bytes
    //We only need to send m-1 shares per iteration as the last one can be recovered using y_i.
    //E.g. for 3 parties and 25 iterations, each entry will have 2x25x256 bits = 1600 bytes
    
    if (DEBUG) cout << "Size per item: " << size_per_item << " bytes" << endl;
    uint32_t N; //polynomial degree for LWE
    if (LOG_NUM_KEYS>20) {N = 4096;} //should be greater than sqrt(number_of_items)
    else {N = 2048;}
    
    // Recommended values: (logt, d) = (12, 2) or (8, 1). 
    uint32_t logt = 12; 
    uint32_t d = 2;

    if (DEBUG == 0) std::cout.setstate(std::ios_base::failbit);

    EncryptionParameters params(scheme_type::BFV);

    PirParams pir_params;

    gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);

    auto time_create_db_s = high_resolution_clock::now();
    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    // Copy of the database. We use this at the end to make sure we retrieved
    // the correct element.
    auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));


    random_device rd;
    auto dbseed = rd() % 256;
    unsigned int dbfact = 3;

    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
            db.get()[(i * size_per_item) + j] = 0;
            db_copy.get()[(i * size_per_item) + j] = 0;
        }
    }



    auto time_create_db_e = high_resolution_clock::now();
    auto time_create_db = duration_cast<microseconds>(time_create_db_e - time_create_db_s).count();
    cout << "Main: PIRServer creates database time: " << time_create_db / 1000 << " ms" << endl;

    // Initialize PIR Server
    PIRServer server(params, pir_params);

    // Initialize PIR client....
    PIRClient client(params, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    // Set galois key for client with id 0
    server.set_galois_key(0, galois_keys);

    // Measure database setup
    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

    // Choose an index of an element in the DB
    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item); // offset in FV plaintext
    if (DEBUG) cout << "Main: element index = " << ele_index << " from [0, " << number_of_items -1 << "]" << endl;
    if (DEBUG) cout << "Main: FV index = " << index << ", FV offset = " << offset << endl; 

    // Measure query generation
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query(index);
    //Here we would need to run ZK proof of well formed, i.e. one "1" and rest zero.
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    
    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply(query, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();

    // Measure response extraction
    auto time_decode_s = chrono::high_resolution_clock::now();
    seal::Plaintext result = client.decode_reply(reply);
    auto time_decode_e = chrono::high_resolution_clock::now();
    auto time_decode_us = duration_cast<microseconds>(time_decode_e - time_decode_s).count();

    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, result, elems.data(), (N * logt) / 8);

    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {
        if (elems[(offset * size_per_item) + i] != db_copy.get()[(ele_index * size_per_item) + i]) {
            cout << "Main: elems " << (int)elems[(offset * size_per_item) + i] << ", db "
                 << (int) db_copy.get()[(ele_index * size_per_item) + i] << endl;
            cout << "Main: PIR result wrong!" << endl;
            return 0;
        }
    }

    if (DEBUG == 0) std::cout.clear();

    cout << "PIRServer pre-processing time: " << time_pre_us / 1000 << " ms" << endl;
    cout << "PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;
    cout << "PIRServer reply generation time: " << time_server_us / 1000 << " ms" << endl;
    cout << "PIRClient answer decode time: " << time_decode_us / 1000 << " ms" << endl;
    if (DEBUG) cout << "Main: Reply num ciphertexts: " << reply.size() << endl;


    //Polynomial interpolation part from Pi_well-formed
    uint64_t modulus = (1 << 13) - 1;
    int degree = N-2; // = N-2 and is even
    int n = degree + 1;
    int N2 = degree + 2;
    std::uniform_int_distribution<int> dist(0, N2);
    
    long missing_index = rd() % degree; 
    if (DEBUG) cout << "Missing index " << missing_index << endl;
    
    PolynomialWithFastVerification p(modulus, N2);
    auto time_decode_polys = chrono::high_resolution_clock::now();

    vector<uint64_t> Px = p.generate_random_evaluation();
    if (DEBUG) std::cout << Px[missing_index] << '\n';
    
    vector<uint64_t> points, values;
    for (int idx = 0; idx <= n; idx++) {
        if (idx == missing_index) continue;
        points.push_back(idx + 1);
        values.push_back(Px[idx]);
    }
    
    uint64_t answer = p.compute_p0(points, values);
    auto time_decode_polye = chrono::high_resolution_clock::now();
    auto time_decode_polyus = duration_cast<microseconds>(time_decode_polye - time_decode_polys).count();
    if (DEBUG) cout << "Answer: " << answer << endl;
    cout << "Polynomial interpolation time: " << time_decode_polyus / 1000 << " ms" << endl;
 
    return (time_pre_us + time_query_us + time_server_us + time_decode_us);
}

