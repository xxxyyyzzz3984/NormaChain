add_library(ecies ecies.cpp)
target_include_directories(ecies PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ecies PUBLIC ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES})

