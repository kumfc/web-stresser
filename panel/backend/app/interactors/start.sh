#!/bin/bash
sudo apt update
sudo apt upgrade
# install make and gcc for building as well as libraries
sudo apt install build-essential libssl-dev autoconf libpcap-dev

cd ~
mkdir -p attack/sources; cd attack/sources

install_slowhttptest() {
    wget https://github.com/shekyan/slowhttptest/archive/v1.8.2.tar.gz -O slowhttptest.tar.gz
    tar -xzvf slowhttptest.tar.gz
    cd slowhttptest-1.8.2
    ./configure --prefix=/usr/
    make
    sudo make install
    cd ..
}

install_hey() {
    wget storage.googleapis.com/hey-release/hey_linux_amd64 -O hey
    sudo cp hey /usr/bin/hey
    sudo chmod a+x /usr/bin/hey
}

install_hping() {
    sudo apt install hping3
}

install_nkiller() {
    wget https://raw.githubusercontent.com/kumfc/web-stresser/master/node/bin/source/nkiller2.1.1.c?token=AHJZO2B6HKSF7YHAJXKYHJ27JZHCE -O nkiller2.c
    gcc nkiller2.c -o nkiller2 -lpcap -lcrypto
    sudo cp nkiller2 /usr/bin/nkiller2
}

install_slowhttptest
install_hey
install_hping
install_nkiller

cd ..