# Smart Home BlockChain Platform
[![Build Status](https://travis-ci.org/yinhaoxiao/Smart-Home-Blockchain-Platform.svg?branch=master)](https://travis-ci.org/yinhaoxiao/Smart-Home-Blockchain-Platform)

This project is a novel two-layer blockchain architecture for the smart home, a consortium chain, and a public chain. In the consortium chain, PBFT is performed to reach a consensus; in the public chain, the nodes are passively waiting for the consensus decision. 
The encryption mechanism is ECIES (ECC + AES + SHA256).

## Installation/Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Dependencies
1. Essentials
```
sudo apt-get -qq update
sudo apt-get install -y cmake build-essential pkg-config libssl-dev
```
2. CMake
```
sudo apt-get install cmake
```

3. OpenSSL
```
sudo apt-get install libssl-dev
```

4. Boost with Boost.Asio
```
sudo apt-get install libboost-all-dev
```


### Compile and Run

Compile with a C++11 compliant compiler

```sh
mkdir build
cd build
cmake ..
make -j4
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

To run `Server`
```
cd build
./Server
```
