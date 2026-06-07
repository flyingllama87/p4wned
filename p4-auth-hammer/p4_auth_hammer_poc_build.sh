#! /bin/bash

g++ \
    -O3 -march=native -flto -funroll-loops \
    -o p4_auth_hammer_poc \
    p4_auth_hammer_poc.cpp \
    -I../include/p4 \
    -I../openssl-1.1.1w/include \
    -L../lib/ \
    -L../openssl-1.1.1w \
    -lp4api -lssl -lcrypto -lrt -ldl -lpthread
