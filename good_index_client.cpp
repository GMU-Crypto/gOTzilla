
#include <chrono>
#include <memory>
#include <random>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <ctime>
#define PORT 12345

using namespace std::chrono;
using namespace std;

inline unsigned int to_uint(char ch)
{
    // EDIT: multi-cast fix as per David Hammen's comment
    return static_cast<unsigned int>(static_cast<unsigned char>(ch));
}



int main(int argc, char *argv[]) {
    unsigned int recvd = 0;
    unsigned int this_recv = 0;
    cout << "Initializing good index verifier..." << endl;

    srand((unsigned)time(NULL) * getpid());  



    //NETWORKING - CLIENT ROLE
    int sock = 0, valread;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "10.193.124.164", &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    else
    {
        cout << "Connected to server" << endl;
    }

    cout << "Receiving ctxts.." << endl;
    uint32_t msgLength;
    recv(sock,&msgLength,sizeof(uint32_t),0); // Receive the message length
    std::cout << "Ctxts length: " <<msgLength <<endl;

    std::vector<unsigned char> pkt ;
    std::string temp ;
    pkt.resize(msgLength,0x00);
    //recv(sock,&(pkt[0]),msgLength,0); // Receive the message data
        recvd = 0;
    do {
      this_recv = recv(sock,&(pkt[0]),msgLength-recvd,0); // Receive the message data
      recvd += this_recv;
    } while (recvd < msgLength);

    temp = { pkt.begin(), pkt.end() } ;

    printf("Ctxts received\n");
    std::cout << "Actual ctxt length: " <<temp.size() <<endl;
    std::cout << "Correctness check:" << to_uint(temp.at(10)) << endl;
 
    cout << "Receiving ptxts.." << endl;
    recv(sock,&msgLength,sizeof(uint32_t),0); // Receive the message length
    std::cout << "Ctxts length: " <<msgLength <<endl;
    pkt.resize(msgLength,0x00);
    recv(sock,&(pkt[0]),msgLength,0); // Receive the message data
    temp = { pkt.begin(), pkt.end() } ;
    printf("Ptxts received\n");
    std::cout << "Actual ptxt length: " <<temp.size() <<endl;
    std::cout << "Correctness check:" << to_uint(temp.at(10)) << endl;

 
    //send ack
    msgLength = 1;
    std::string ack = "1";
    std::cout << "() Sending ack of length " << msgLength << endl;
    send(sock,&msgLength ,sizeof(uint32_t) ,0); // Send the message length
    send(sock,ack.c_str() ,msgLength ,0); // Send the message data 
    std::cout << "() Ack sent." << endl;

    return 0;
}
