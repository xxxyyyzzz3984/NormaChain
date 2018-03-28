cmake_minimum_required(VERSION 2.8)

project(IoT_BlockChain)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#find_package(Threads REQUIRED)

######### finding OpenSSL Libraries #####

find_package ( OpenSSL REQUIRED )
if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL (include: ${OPENSSL_INCLUDE_DIR}, library: ${OPENSSL_LIBRARIES})")
else()
    message(STATUS "  package 'OpenSSL' not found")
endif()

##############


add_subdirectory (src)

add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC eccverf ${OPENSSL_LIBRARIES})

#subdirs(src)
#set(SRC_LIST src/main.cpp)
#add_executable(${PROJECT_NAME} ${SRC_LIST})

#target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})
