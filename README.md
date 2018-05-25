

# NormaChain
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/yinhaoxiao/Smart-Home-Blockchain-Platform/blob/master/LICENSE)

This is the implementation of NormaChain prototype. The structure of NormaChain is shown as follow:
<h1 align="center">
	<img width="50%" src="https://github.com/yinhaoxiao/Smart-Home-Blockchain-Platform/blob/master/image.jpg" alt="logo">
</h1>

## Installation/Getting Started

These instructions will help you to set up, build and run our project.

### Dependencies
1. Essentials
```
sudo apt-get -qq update
sudo apt-get install -y build-essential pkg-config
```
2. CMake
```
sudo apt-get install cmake
```

3. OpenSSL Library
```
sudo apt-get install libssl-dev
```

4. Boost Library with Boost.Asio
```
sudo apt-get install libboost-all-dev
```

5. GMP Library
```
sudo apt-get install libgmp3-dev
```

6. [PBC Library](https://crypto.stanford.edu/pbc)
```
./configure --prefix=$HOME/.local
make
sudo make install all
```


### Compile and Run

Compile with a C++11 compliant compiler

```sh
mkdir build
cd build
cmake ..
make -j 4
```

To run `buyer`
```
cd build
./test_buyer
```

To run `seller`
```
cd build
./test_seller
```

To run `approver`
```
cd build
./test_approver path/to/approver/info
```

To run `agent`
```
cd build
./test_agent
```

To run `supervisor`
```
cd build
./test_supervisor keyword
```
