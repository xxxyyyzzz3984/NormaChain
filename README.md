# BlockChain Platform

This project is a novel blockchain distributed concensus framework based on revised PBFT (with $O(nlog(n))$ computational overhead), and faster encryption/decryption mechanism (ECIES, i.e., ECC+AES+SHA256). 

## Installation/Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Dependencies

1. OpenSSL
```
sudo apt-get install libssl-dev
```

2. Boost (Minimum version 1.55 with Boost.Asio)
```
sudo apt-get install libboost-all-dev
```


### Compile and Run

Compile with a C++11 compliant compiler

```sh
mkdir build
cd build
cmake ..
make
cd ..
```
