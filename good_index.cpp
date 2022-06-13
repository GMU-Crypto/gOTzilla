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

#include "FHE/FHE_Keys.h"
#include "FHE/NTL-Subs.h"
#include "Math/Setup.h"
#include "FHE/NoiseBounds.h"
#include "FHEOffline/Proof.h"
#include "FHEOffline/Prover.h"
#include "FHE/AddableVector.h"
#include "FHE/Plaintext.h"
#include "FHE/Ciphertext.h"
#include "FHE/Ring_Element.h"


#include "constants.h"
#include "good_index.h"
#define NETWORKING 0
#define PORT 12345
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::microseconds;

std::string gen_random2(const int len) {
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

inline unsigned int to_uint(char ch)
{
    return static_cast<unsigned int>(static_cast<unsigned char>(ch));
}


void run_good_index(uint64_t ele_index) {
    uint64_t sqrt_N = 1<<(LOG_NUM_KEYS/2); // Assumes LOG_NUM_KEYS is even
    auto time_pre_index = high_resolution_clock::now();
    good_index(sqrt_N, ele_index / sqrt_N, ele_index % sqrt_N);
    auto time_post_index = high_resolution_clock::now();
    auto time_index_us = duration_cast<microseconds>(time_post_index - time_pre_index).count();
    cout << "Well-formed query proof time: " << time_index_us / 1000 << endl;
}

void run_good_index_network(uint64_t ele_index) {
    uint64_t sqrt_N = 1<<(LOG_NUM_KEYS/2); // Assumes LOG_NUM_KEYS is even
    good_index_network(sqrt_N, ele_index / sqrt_N, ele_index % sqrt_N);
}

void good_index(uint64_t num_items, uint64_t row_index, uint64_t col_index) {

    uint64_t M = num_items; // TODO: check why prev line was in original code
    if (DEBUG) cout << "numbits(M) " << numBits(M) << endl;

    FHE_Params params = FHE_Params(0); // 0 multiplications needed
    FFT_Data FieldD;
    int extra_slack;
    bigint p0;
    int lgp0;
    int sec = 40;
    PRNG G;
    G.ReSeed();
    // based on setup procedure from MP-SPDZ/FHE/NTL-Subs.cpp
    if (DEBUG) cout << "Generating (" << numBits(M) << "," << M << ")" << endl;
    bigint p = generate_prime(numBits(M), M);
    if (DEBUG) cout << "test prime: " << p << endl;
    FHE_Params tmp_params;
    while (true) {
	tmp_params = params;
	SemiHomomorphicNoiseBounds nb(p, phi_N(M), 1, sec,
        	  numBits(NonInteractiveProof::slack(sec, phi_N(M))), true, tmp_params);
    	p0 = p;
	if (DEBUG) cout << "min_p0: " << nb.min_p0() << endl;
    	while (nb.min_p0() > p0)
            {
          	p0 <<= 1;
            }
	if (DEBUG) cout << "min_phi_m: " << nb.min_phi_m(2+numBits(p0),params.get_R()) << endl;
      	if (phi_N(M) < nb.min_phi_m(2 + numBits(p0), params.get_R()) || (uint64_t)phi_N(M) < num_items || p < phi_N(M))
            {
          	M <<= 1;
		generate_prime(p, numBits(M), M);
		if (DEBUG) cout << "new test prime: " << p << endl;
            }
	else
	    {
		lgp0 = numBits(p0)+1;
		break;
	    }
    }
    params = tmp_params;
    extra_slack = common_semi_setup(params, M, p, lgp0, 0, true);

    FieldD.init(params.get_ring(), p);
    gfp::init_field(p);

    if (DEBUG) cout << "Index proof prime: " << FieldD.get_prime() << "\t\tphi(m): " << FieldD.num_slots() << "\t\textra slack: " << extra_slack << endl;
    FHE_KeyPair keys(params, FieldD.get_prime());
    keys.generate(G);

    CowGearOptions::singleton.set_top_gear(true);
    NonInteractiveProof proof = NonInteractiveProof(sec, keys.pk, extra_slack);
    if (DEBUG) cout << "U: " << proof.U << " V: " << proof.V << endl;

    FHE_PK pk = keys.pk;

    octetStream ctxts, ptxts;
    AddableVector<Ciphertext> c;
    c.resize(proof.U, pk.get_params());
    vector<Plaintext_<FFT_Data> > m;
    m.resize(proof.U, FieldD);


    // based on MP-SPDZ/FHEOffline/SimpleEncCommit.cpp-NonInteractiveProofSimpleEncCommit<FD>::generate_proof
    Proof::Randomness r(proof.U, pk.get_params());    
	    for (auto& mess : m) mess.randomize(G);
	    m[0].assign_zero();
	    m[0].set_element(row_index,1);
	    m[1].assign_zero();
	    m[1].set_element(col_index,1);
	    Random_Coins rc(pk.get_params());
	    c.resize(proof.U, pk);
	    r.resize(proof.U, pk);
	    for (unsigned i = 0; i < proof.U; i++)
	    {
         //will need to save randomness b/w runs for verifiability
	        rc.generate(G);
	        pk.encrypt(c[i], m.at(i), rc);
	    }
    
    Prover<FFT_Data, Plaintext_<FFT_Data> > prover(proof, FieldD);
    size_t prover_memory = prover.NIZKPoK(proof, ctxts, ptxts, pk, c, m, r);
    
    cout << "Bdd noise report_size " << prover_memory << endl;
    MemoryUsage mu;
    prover.report_size(CAPACITY, mu);
    cout << "Bdd noise memory usage: " << endl;
    mu.print();

    if (proof.top_gear)
    {
        c += c;
        for (auto& mm : m)
            mm += mm;
    }
    
    cout << "Bdd noise Communication " << (ctxts.get_length() + ptxts.get_length())/1024 << " kb" << endl;

}


void good_index_network(uint64_t num_items, uint64_t row_index, uint64_t col_index) {

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
        cout << "Listening for good index..." << endl;
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
    auto timer_start = high_resolution_clock::now();


    //uint64_t M = std::max((uint64_t)1024,num_items);
    uint64_t M = num_items; // TODO: check why prev line was in original code
    if (DEBUG) cout << "numbits(M) " << numBits(M) << endl;

    FHE_Params params = FHE_Params(0); // 0 multiplications needed
    FFT_Data FieldD;
    int extra_slack;
    bigint p0;
    int lgp0;
    int sec = 40;
    PRNG G;
    G.ReSeed();
    // based on setup procedure from MP-SPDZ/FHE/NTL-Subs.cpp
    if (DEBUG) cout << "Generating (" << numBits(M) << "," << M << ")" << endl;
    bigint p = generate_prime(numBits(M), M);
    if (DEBUG) cout << "test prime: " << p << endl;
    FHE_Params tmp_params;
    while (true) {
	tmp_params = params;
	SemiHomomorphicNoiseBounds nb(p, phi_N(M), 1, sec,
        	  numBits(NonInteractiveProof::slack(sec, phi_N(M))), true, tmp_params);
    	p0 = p;
	if (DEBUG) cout << "min_p0: " << nb.min_p0() << endl;
    	while (nb.min_p0() > p0)
            {
          	p0 <<= 1;
            }
	if (DEBUG) cout << "min_phi_m: " << nb.min_phi_m(2+numBits(p0),params.get_R()) << endl;
      	if (phi_N(M) < nb.min_phi_m(2 + numBits(p0), params.get_R()) || (uint64_t)phi_N(M) < num_items || p < phi_N(M))
            {
          	M <<= 1;
		generate_prime(p, numBits(M), M);
		if (DEBUG) cout << "new test prime: " << p << endl;
            }
	else
	    {
		lgp0 = numBits(p0)+1;
		break;
	    }
    }
    params = tmp_params;
    extra_slack = common_semi_setup(params, M, p, lgp0, 0, true);

    FieldD.init(params.get_ring(), p);
    gfp::init_field(p);

    cout << "Index proof prime: " << FieldD.get_prime() << "\t\tphi(m): " << FieldD.num_slots() << "\t\textra slack: " << extra_slack << endl;
    FHE_KeyPair keys(params, FieldD.get_prime());
    keys.generate(G);

    CowGearOptions::singleton.set_top_gear(true);
    NonInteractiveProof proof = NonInteractiveProof(sec, keys.pk, extra_slack);
    if (DEBUG) cout << "U: " << proof.U << " V: " << proof.V << endl;

    FHE_PK pk = keys.pk;

    octetStream ctxts, ptxts;
    AddableVector<Ciphertext> c;
    c.resize(proof.U, pk.get_params());
    vector<Plaintext_<FFT_Data> > m;
    m.resize(proof.U, FieldD);


    // based on MP-SPDZ/FHEOffline/SimpleEncCommit.cpp-NonInteractiveProofSimpleEncCommit<FD>::generate_proof
    Proof::Randomness r(proof.U, pk.get_params());
    
	    for (auto& mess : m) mess.randomize(G);
	    m[0].assign_zero();
	    m[0].set_element(row_index,1);
	    m[1].assign_zero();
	    m[1].set_element(col_index,1);
	    Random_Coins rc(pk.get_params());
	    c.resize(proof.U, pk);
	    r.resize(proof.U, pk);
	    for (unsigned i = 0; i < proof.U; i++)
	    {
        	//r[i].sample(G); //will need to save randomness b/w runs for verifiability
	        //rc.assign(r[i]);
	        rc.generate(G);
	        pk.encrypt(c[i], m.at(i), rc);
	    }
    
    Prover<FFT_Data, Plaintext_<FFT_Data> > prover(proof, FieldD);
    size_t prover_memory = prover.NIZKPoK(proof, ctxts, ptxts, pk, c, m, r);
    
    cout << "Bdd noise report_size " << prover_memory << endl;
    MemoryUsage mu;
    prover.report_size(CAPACITY, mu);
    cout << "Bdd noise memory usage: " << endl;
    mu.print();

    if (proof.top_gear)
    {
        c += c;
        for (auto& mm : m)
            mm += mm;
    }
    
    cout << "Bdd noise Communication " << (ctxts.get_length() + ptxts.get_length())/1024 << " kb" << endl;

    std::string rand_ctxts = gen_random2(ctxts.get_length());
    std::string rand_ptxts = gen_random2(ptxts.get_length());
    std::vector<unsigned char> pkt ;
    std::string temp ;

    uint32_t msgLength = rand_ctxts.length();
    //uint32_t sndMsgLength = htonl(msgLength); // Ensure network byte order
    std::cout << "(3) Sending ctexts..." << endl;
    send(new_socket,&msgLength ,sizeof(uint32_t) ,0); // Send the message length
    send(new_socket,rand_ctxts.c_str() ,msgLength ,0); // Send the message data 
    std::cout << "(3) Correctness test for ctexts:"  << to_uint(rand_ctxts.at(10)) << endl;

    msgLength = rand_ptxts.length();
    //sndMsgLength = htonl(msgLength); // Ensure network byte order
    std::cout << "(3) Sending ptexts..." << endl;
    send(new_socket,&msgLength ,sizeof(uint32_t) ,0); // Send the message length
    send(new_socket,rand_ptxts.c_str() ,msgLength ,0); // Send the message data 
    std::cout << "(3) Correctness test for ptexts:"  << to_uint(rand_ptxts.at(10)) << endl;

    cout << "Receiving ack" << endl;
    recv(new_socket,&msgLength,sizeof(uint32_t),0); // Receive the message length
    std::cout << "Ack length: " <<msgLength <<endl;
    pkt.resize(msgLength,0x00);
    recv(new_socket,&(pkt[0]),msgLength,0); // Receive the message data
    temp = { pkt.begin(), pkt.end() } ;
    printf("Ack received\n");
    std::cout << "Actual ack length: " <<temp.size() <<endl;


    auto timer_fin = high_resolution_clock::now();
    auto time_index_tot = duration_cast<microseconds>(timer_fin - timer_start).count();
    cout << "Well-formed query proof time (incl. latency): " << time_index_tot / 1000 << "ms" << endl;


}
