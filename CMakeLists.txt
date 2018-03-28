cmake_minimum_required(VERSION 2.8)

project(IoT_BlockChain)

#find_package(Threads REQUIRED)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
find_package ( CryptoPP REQUIRED )

if(CRYPTOPP_FOUND)
    message(STATUS "Found crypto++ (include: ${CRYPTOPP_INCLUDE_DIRS}, library: ${CRYPTOPP_LIBRARIES})")
else()
    message(STATUS "package 'crypto++' not found")
endif()

add_subdirectory (src)

add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC eccverf ${CRYPTOPP_LIBRARIES})

#subdirs(src)
#set(SRC_LIST src/main.cpp)
#add_executable(${PROJECT_NAME} ${SRC_LIST})

#target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})
