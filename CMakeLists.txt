cmake_minimum_required(VERSION 2.8)

project(IoT_BlockChain)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

######### finding OpenSSL Libraries #####
find_package ( OpenSSL REQUIRED )

if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL (include: ${OPENSSL_INCLUDE_DIR}, library: ${OPENSSL_LIBRARIES})")
else()
    message(STATUS "Package 'OpenSSL' not found")
endif()
##############

############# finding Boost Libraries ######
find_package(Boost REQUIRED COMPONENTS system thread)

if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  link_directories(${Boost_LIBRARY_DIRS})
endif(Boost_FOUND)

SET(BOOST_LIBS ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY})
##############

############# finding THREAD Libraries ######
find_package(Threads REQUIRED)
##############

add_subdirectory (src)

add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC ecies eccverify configparser
    ${OPENSSL_LIBRARIES} ${BOOST_LIBS} ${CMAKE_THREAD_LIBS_INIT})
