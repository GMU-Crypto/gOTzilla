// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

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

#define NETWORKING 0 
// Also set at SEAL/native/examples/verifier_state.cpp and MP-SPDZ/good_index.cpp
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
#define PORT 12345


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
    // EDIT: multi-cast fix as per David Hammen's comment
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

/*
Helper function: Prints the name of the example in a fancy banner.
*/
void print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

        cout << endl
            << banner_top << endl
            << banner_middle << endl
            << banner_top << endl
            << endl;
    }
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(shared_ptr<SEALContext> context)
{
    // Verify parameters
    if (!context)
    {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->context_data();

    /*
    Which scheme are we using?
    */
    string scheme_name;
    switch (context_data.parms().scheme())
    {
    case scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw invalid_argument("unsupported scheme");
    }

    cout << "/ Encryption parameters:" << endl;
    cout << "| scheme: " << scheme_name << endl;
    cout << "| poly_modulus_degree: " << 
        context_data.parms().poly_modulus_degree() << endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "| coeff_modulus size: " << context_data.
        total_coeff_modulus_bit_count() << " bits" << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == scheme_type::BFV)
    {
        cout << "| plain_modulus: " << context_data.
            parms().plain_modulus().value() << endl;
    }

    cout << "\\ noise_standard_deviation: " << context_data.
        parms().noise_standard_deviation() << endl;
    cout << endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
ostream &operator <<(ostream &stream, parms_id_type parms_id)
{
    stream << hex << parms_id[0] << " " << parms_id[1] << " "
        << parms_id[2] << " " << parms_id[3] << dec;
    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template<typename T>
void print_vector(vector<T> vec, size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);

    size_t slot_count = vec.size();

    cout << fixed << setprecision(prec) << endl;
    if(slot_count <= 2 * print_size)
    {
        cout << "    [";
        for (size_t i = 0; i < slot_count; i++)
        {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(max(vec.size(), 2 * print_size));
        cout << "    [";
        for (size_t i = 0; i < print_size; i++)
        {
            cout << " " << vec[i] << ",";
        }
        if(vec.size() > 2 * print_size)
        {
            cout << " ...,";
        }
        for (size_t i = slot_count - print_size; i < slot_count; i++)
        {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    cout << endl;

    /*
    Restore the old std::cout formatting.
    */
    cout.copyfmt(old_fmt);
}

void example_sealpir();

void oneofnot();

void poly_interp_network();

int main()
{
    cout << "************Running oneofnot************" <<  endl;
    
    oneofnot(); 
 
    cout << "************Running goodindex************" <<  endl;
    run_good_index(0);


    cout << "************Running run_verifier_state************" <<  endl;

    run_verifier_state();
    //if (NETWORKING) {run_good_index_network(0);} else {run_good_index(0);} // fill in parameter with correct index
    //if (NETWORKING) {poly_interp_network();} else {oneofnot();}
    //if (NETWORKING) {run_verifier_state_network();} else {run_verifier_state();}
    
    //example_sealpir();
    return 0;
}

void oneofnot() {

    uint64_t number_of_items = NUM_KEYS;
    cout << "Number of items: " << number_of_items << endl;
    uint64_t size_per_item = 1600; // in bytes
    //Yeah, we need 3 parties and 25 iterations. 
    //However, we only need to send m-1 shares per iteration as the last one can be recovered using y_i.
    // So each entry will have 2x25x256 bits = 1600 bytes
    
    //uint64_t size_per_item = 128; // in bytes
    cout << "Size per item: " << size_per_item << " bytes" << endl;
    uint32_t N = 4096;

    // Recommended values: (logt, d) = (12, 2) or (8, 1). 
    uint32_t logt = 12; 
    uint32_t d = 2;

    //if (DEBUG == 0) std::cout.setstate(std::ios_base::failbit);

    EncryptionParameters params(scheme_type::BFV);

    PirParams pir_params;

    gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);

    auto time_create_db_s = high_resolution_clock::now();
    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    //std::cout << typeid(db).name() << '\n';
    // Copy of the database. We use this at the end to make sure we retrieved
    // the correct element.
    auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));


    random_device rd;
    auto dbseed = rd() % 256;
    unsigned int dbfact = 3;

    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
            //auto val = dbseed*dbfact % 3;
            db.get()[(i * size_per_item) + j] = 0;
            db_copy.get()[(i * size_per_item) + j] = 0;
        }
    }

/*
uint8_t *ptr = db.get();
for (uint64_t i = 0; i < number_of_items*size_per_item; i++) {
*ptr = 0;
ptr++;
}


*/


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
    //add code for server to verify that query has correct format, i.e. one "1" and rest zero.
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
            return;
        }
    }

    //if (DEBUG == 0) std::cout.clear();


    cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1000 << " ms" << endl;
    cout << "Main: PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;
    cout << "Main: PIRServer reply generation time: " << time_server_us / 1000 << " ms"
         << endl;
    cout << "Main: PIRClient answer decode time: " << time_decode_us / 1000 << " ms" << endl;
    cout << "Main: Reply num ciphertexts: " << reply.size() << endl;

    //To marshall query to send over the network, you can use serialize/deserialize:
    //std::string query_ser = serialize_query(query);
    //PirQuery query2 = deserialize_query(d, 1, query_ser, CIPHER_SIZE);

    
    // TODO: Prover and Verifier interact to prove that the query has the correct form.
    // query[i] = Enc(v_i) where v_i = (0, ..., 0, 1, 0, ..., 0)
    // Verifier receives Enc(v_i), compute r_i * Enc(v_i) + w_i
    // r_i is a random scalar;
    // w_i encodes the secret.
    // Let P_i(x) = s_i + a_1*x + ... + a_{N-2}*x^{N-2}
    // w_i[j] = P_i[j] for j = 0...N-1.
    // So, r_i*Enc(v_i) + w_i = (w_i[0], ..., w_i[j-1], w_i[j] + r_i, w_i[j+1], ..., w_i[N-1]).
    // If the prover is honest, the prover can reconstruct s_i.
    // Repeat a few times to amplify the soundness to 2^-40}

/*
    uint64_t sqrt_N = 1<<(LOG_NUM_KEYS/2); // Assumes LOG_NUM_KEYS is even 
    auto time_pre_index = high_resolution_clock::now();
    good_index(sqrt_N, ele_index / sqrt_N, ele_index % sqrt_N);
    auto time_post_index = high_resolution_clock::now();
    auto time_index_us = duration_cast<microseconds>(time_post_index - time_pre_index).count();
    cout << "Well-formed query proof time: " << time_index_us / 1000 << endl;
*/

    

    //Polynomial interpolation test code
    uint64_t modulus = (1 << 13) - 1;
    int degree = N-2; // = N-2 and is even
    int n = degree + 1;
    int N2 = degree + 2;
    std::uniform_int_distribution<int> dist(0, N2);
    
    //cout << dist. << endl;
    //std::cout << typeid(db).name() << '\n';

    //long missing_index = ele_index;
    long missing_index = rd() % degree; //Is this correct?
    cout << "Missing index " << missing_index << endl;
    
    PolynomialWithFastVerification p(modulus, N2);
    auto time_decode_polys = chrono::high_resolution_clock::now();

    vector<uint64_t> Px = p.generate_random_evaluation();
    std::cout << Px[missing_index] << '\n';
    
    vector<uint64_t> points, values;
    for (int idx = 0; idx <= n; idx++) {
        if (idx == missing_index) continue;
        points.push_back(idx + 1);
        values.push_back(Px[idx]);
    }
    
    uint64_t answer = p.compute_p0(points, values);
    auto time_decode_polye = chrono::high_resolution_clock::now();
    auto time_decode_polyus = duration_cast<microseconds>(time_decode_polye - time_decode_polys).count();
    cout << "Answer: " << answer << endl;
    cout << "Polynomial interpolation time: " << time_decode_polyus / 1000 << " ms" << endl;
 

}

void poly_interp_network() {

    //uint32_t N = LOG_NUM_KEYS < 20 ? 1024 : 2048; //degree polynomial for LWE
    uint32_t N = 2048;
    random_device rd;
    std::string seed = gen_random(16);
    std::string c_i = gen_random(131088);


    //Setting up network socket - server role
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
       
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
       
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
       
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, 
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "Listening for poly interp..." << endl;
    }

    //Step 2 Wait for connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "(2) Connection accepted" << endl;
    }


    //ctxts_ser = ctxts::str();
    //uint32_t msgLength = ctxts.get_length();
    //uint32_t sndMsgLength = htonl(msgLength); // Ensure network byte order
    //std::cout << "(3) Sending ctexts..." << endl;
    //send(new_socket,&sndMsgLength ,sizeof(uint32_t) ,0); // Send the message length
    //send(new_socket,ctxts.serialize() ,msgLength ,0); // Send the message data 
    //std::cout << "(3) Correctness test for ctexts:"  << ctxts.hash() << endl;





    //Polynomial interpolation test code
    auto time_decode_polys = chrono::high_resolution_clock::now();


    //Client: Receive 2x2x64xN bits= 65536 bytes

    cout << "Receiving first reply.." << endl;
    uint32_t msgLength = seed.length();
    recv(new_socket,&msgLength,sizeof(uint32_t),0); // Receive the message length
    std::cout << "First reply length: " <<msgLength <<endl;

    std::vector<unsigned char> pkt ;
    std::string temp ;
    pkt.resize(msgLength,0x00);
    recv(new_socket,&(pkt[0]),msgLength,0); // Receive the message data
    temp = { pkt.begin(), pkt.end() } ;

    std::cout << "() First reply received." << endl;
    std::cout << "Actual reply length: " <<temp.size() <<endl;
    std::cout << "Correctness check:" << to_uint(temp.at(10)) << endl;



    uint64_t modulus = (1 << 13) - 1;
    int degree = N-2; // = N-2 and is even
    int n = degree + 1;
    int N2 = degree + 2;
    std::uniform_int_distribution<int> dist(0, N2);
    
    //cout << dist. << endl;
    //std::cout << typeid(db).name() << '\n';

    //long missing_index = ele_index;
    long missing_index = rd() % degree; //Is this correct?
    cout << "Missing index " << missing_index << endl;
    
    PolynomialWithFastVerification p(modulus, N2);

    vector<uint64_t> Px = p.generate_random_evaluation();
    std::cout << Px[missing_index] << '\n';
    
    sleep_for(1000000ns);

    //Server: Comm(seed) (not listed?) send random 16 bytes at line 346
    //Enc(Px)+r*Enc(query) (not listed) simulate N*64*2 *4 bits
    // = 131088 bytes total

    msgLength = c_i.length();
    std::cout << "c_i length: " <<msgLength <<endl;
    //uint32_t sndMsgLength = htonl(msgLength); // Ensure network byte order
    std::cout << "() Sending c_i..." << endl;
    send(new_socket,&msgLength ,sizeof(uint32_t) ,0); // Send the message length
    send(new_socket,c_i.c_str() ,msgLength ,0); // Send the message data 
    std::cout << "() c_i sent." << endl;
    std::cout << "Correctness check:" << to_uint(c_i.at(10)) << endl;  



    vector<uint64_t> points, values;
    for (int idx = 0; idx <= n; idx++) {
        if (idx == missing_index) continue;
        points.push_back(idx + 1);
        values.push_back(Px[idx]);
    }
    
    uint64_t answer = p.compute_p0(points, values);


    sleep_for(1000000ns);
    //Client receive: Comm(answer) (not listed) receive 16 bytes after 372
    cout << "Receiving Comm(answer).." << endl;
    msgLength = seed.length();
    recv(new_socket,&msgLength,sizeof(uint32_t),0); // Receive the message length
    std::cout << "Comm(answer) length: " <<msgLength <<endl;
    pkt.resize(msgLength,0x00);
    recv(new_socket,&(pkt[0]),msgLength,0); // Receive the message data
    temp = { pkt.begin(), pkt.end() } ;
    std::cout << "() Comm(answer) received." << endl;
    std::cout << "Actual Comm(answer) length: " <<temp.size() <<endl;
    std::cout << "Correctness check:" << to_uint(temp.at(10)) << endl;

    sleep_for(1000000ns);

    //Server: Decommit seed = 128 bits = 16 bytes
    msgLength = seed.length();
    std::cout << "Seed length: " <<msgLength <<endl;
    //uint32_t sndMsgLength = htonl(msgLength); // Ensure network byte order
    std::cout << "() Sending seed..." << endl;
    send(new_socket,&msgLength ,sizeof(uint32_t) ,0); // Send the message length
    send(new_socket,seed.c_str() ,msgLength ,0); // Send the message data 
    std::cout << "() Seed sent." << endl;
    std::cout << "Correctness check:" << to_uint(seed.at(10)) << endl;

    sleep_for(1000000ns);

    //Client: Receive answer (double check with Phi hung)
    cout << "Receiving answer.." << endl;
    msgLength = seed.length();
    recv(new_socket,&msgLength,sizeof(uint32_t),0); // Receive the message length
    std::cout << "answer length: " <<msgLength <<endl;
    pkt.resize(msgLength,0x00);
    recv(new_socket,&(pkt[0]),msgLength,0); // Receive the message data
    temp = { pkt.begin(), pkt.end() } ;
    std::cout << "() answer received." << endl;
    std::cout << "Actual answer length: " <<temp.size() <<endl;
    std::cout << "Correctness check:" << to_uint(temp.at(5)) << endl;


/*
    //Server: Comm(seed) (not listed?) send random 16 bytes at line 346
    msgLength = seed.length();
    std::cout << "Seed length: " <<msgLength <<endl;
    //uint32_t sndMsgLength = htonl(msgLength); // Ensure network byte order
    std::cout << "() Sending seed..." << endl;
    send(new_socket,&msgLength ,sizeof(uint32_t) ,0); // Send the message length
    send(new_socket,seed.c_str() ,msgLength ,0); // Send the message data 
    std::cout << "() Seed sent." << endl;
    std::cout << "Correctness check:" << to_uint(seed.at(10)) << endl;
*/




    auto time_decode_polye = chrono::high_resolution_clock::now();
    auto time_decode_polyus = duration_cast<microseconds>(time_decode_polye - time_decode_polys).count();
    cout << "Answer: " << answer << endl;
    cout << "Polynomial interpolation time (incl. latency costs): " << time_decode_polyus / 1000 << " ms" << endl;


}

void example_sealpir() {
    //uint64_t number_of_items = 1 << 12;
    uint64_t number_of_items = 1 << 14;
    cout << "Number of items: " << number_of_items << endl;
    //2^27 goal.
    //uint64_t size_per_item = 1280; // in bytes
    uint64_t size_per_item = 128; // in bytes
    cout << "Size per item: " << size_per_item << " bytes" << endl;
    uint32_t N = 1024; //degree polynomial for LWE
    //N^d should be greater than number_of_items. 2^14?

    // Recommended values: (logt, d) = (12, 2) or (8, 1). 
    uint32_t logt = 12; 
    uint32_t d = 2;

    EncryptionParameters params(scheme_type::BFV);
    PirParams pir_params;

    // Generates all parameters
    cout << "Main: Generating all parameters" << endl;
    gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);

    cout << "Main: Initializing the database (this may take some time) ..." << endl;

    // TODO: replace the random database with the one we need to OT.
    // Public input: (y_1, ..., y_n)
    // MPCiTH params: we use 4 parties, with 20 iterations to get 2^{-40} soundness.
    // The data length = 4x20x256 = 20480 bits = 2560 bytes
    // Work on line 296 - 313
    
    auto time_create_db_s = high_resolution_clock::now();
    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    //std::cout << typeid(db).name() << '\n';

    // Copy of the database. We use this at the end to make sure we retrieved
    // the correct element.
    auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));

    


    random_device rd;
    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
            auto val = rd() % 256;
            db.get()[(i * size_per_item) + j] = val;
            db_copy.get()[(i * size_per_item) + j] = val;
        }
    }

/*
    auto seed = db[0];
    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
            auto seed = emp::PRG(&db[0]);
            db.get()[(i * size_per_item) + j] = seed;
            db_copy.get()[(i * size_per_item) + j] = seed;
        }
    }*/

    cout << "DB: " << db.get()[7] << endl;

    cout << "DB: " << &db << endl;
    
    auto a = emp::PRG(&db[0]);

    //std::cout << typeid(&db[0]).name() << '\n';

    cout << "prg: " << &a << endl;

    auto b = emp::PRG(a);

    cout << "prg: " << &b << endl;

    auto time_create_db_e = high_resolution_clock::now();
    auto time_create_db = duration_cast<microseconds>(time_create_db_e - time_create_db_s).count();
    cout << "Main: PIRServer creates database time: " << time_create_db / 1000 << " ms" << endl;
    
    // Initialize PIR Server
    cout << "Main: Initializing server and client" << endl;
    PIRServer server(params, pir_params);

    // Initialize PIR client....
    PIRClient client(params, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    cout << "Main: Galois keys size: " << galois_keys.size() << endl;
    // Set galois key for client with id 0
    cout << "Main: Setting Galois keys...";
    server.set_galois_key(0, galois_keys);

    // Measure database setup
    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    cout << "Main: database pre processed " << endl;
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

    // Choose an index of an element in the DB
    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item); // offset in FV plaintext
    cout << "Main: element index = " << ele_index << " from [0, " << number_of_items -1 << "]" << endl;
    cout << "Main: FV index = " << index << ", FV offset = " << offset << endl; 

    // Measure query generation
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query(index);
    //add code for server to verify that query has correct format, i.e. one "1" and rest zero.
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    //To marshall query to send over the network, you can use serialize/deserialize:
    //std::string query_ser = serialize_query(query);
    //PirQuery query2 = deserialize_query(d, 1, query_ser, CIPHER_SIZE);

    // TODO: Prover and Verifier interact to prove that the query has the correct form.
    // query[i] = Enc(v_i) where v_i = (0, ..., 0, 1, 0, ..., 0)
    // Verifier receives Enc(v_i), compute r_i * Enc(v_i) + w_i
    // r_i is a random scalar;
    // w_i encodes the secret.
    // Let P_i(x) = s_i + a_1*x + ... + a_{N-2}*x^{N-2}
    // w_i[j] = P_i[j] for j = 0...N-1.
    // So, r_i*Enc(v_i) + w_i = (w_i[0], ..., w_i[j-1], w_i[j] + r_i, w_i[j+1], ..., w_i[N-1]).
    // If the prover is honest, the prover can reconstruct s_i.
    // Repeat a few times to amplify the soundness to 2^-40}
    
    
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
            return;
        }
    }

    // Output results
    cout << "Main: PIR result correct!" << endl;
    cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1000 << " ms" << endl;
    cout << "Main: PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;
    cout << "Main: PIRServer reply generation time: " << time_server_us / 1000 << " ms"
         << endl;
    cout << "Main: PIRClient answer decode time: " << time_decode_us / 1000 << " ms" << endl;
    cout << "Main: Reply num ciphertexts: " << reply.size() << endl;
}

