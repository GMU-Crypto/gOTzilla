# gOTzilla proof of concept code

This code is a proof of concept implementation for gOTzilla: Efficient Disjunctive Zero-Knowledge Proofs from MPC in the Head, with Application to Proofs of Assets in Cryptocurrencies https://eprint.iacr.org/2022/170

Main parameter: LOG_NUM_KEYS in constants.h (need 32GB RAM for 2^20 elements and 384GB RAM for 2^24 elements)

Tested on Ubuntu 20.04 LTS (need at least 16GB RAM for compilation).
After `git clone`, run `install.sh` (which sets up all necessary dependencies - needs ~20min on 8-core CPU), then run executable `bin/gotzilla`.
