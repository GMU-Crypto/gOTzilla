#!/bin/sh

sudo apt update && sudo apt-get install -y cmake build-essential automake build-essential git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm libgmp3-dev
cd ~
git clone https://github.com/weidai11/cryptopp/ && cd cryptopp && make -j8 && sudo make install && cd ~
git clone --branch 3.2.0 https://github.com/Microsoft/SEAL/ && cd ~/SEAL/native/src && sudo cmake . && sudo make -j8 && sudo make install && cd ~
git clone https://github.com/microsoft/SealPIR && cd SealPIR && git reset --hard ccf86c50fd3291d7d720f1b9547022ebf3c9b6b0 && cmake . && make -j8 && cd ~
git clone https://github.com/data61/MP-SPDZ && cd MP-SPDZ && make -j8 tldr && make -j8 && cd ~
git clone https://github.com/emp-toolkit/emp-tool && cd emp-tool && cmake . && make -j8 && sudo make install && cd ~
cd ~/gOTzilla && cmake . && make -j8
