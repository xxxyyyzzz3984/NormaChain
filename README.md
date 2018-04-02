# BlockChain Platform

This project is a novel blockchain distributed concensus framework based on revised PBFT (with <a href="https://www.codecogs.com/eqnedit.php?latex=O(n\log&space;(n))" target="_blank"><img src="https://latex.codecogs.com/gif.latex?O(n\log&space;(n))" title="O(n\log (n))" /></a> computational overhead), and faster public key asymmetric encryption/decryption mechanism (ECIES, i.e., ECC+AES+SHA256). 

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

To run `Verifier`
```
cd build
./Verifier
```

To run `Proofer`
```
cd build
./Proofer
```
