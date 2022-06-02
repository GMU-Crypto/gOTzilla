#ifndef SHARE_AT_H
#define SHARE_AT_H
#include <cryptopp/modarith.h>

using namespace CryptoPP;

void share_at(CryptoPP::byte *output_shares, CryptoPP::byte *input, size_t input_len, Integer K, CryptoPP::byte *r);

#endif
