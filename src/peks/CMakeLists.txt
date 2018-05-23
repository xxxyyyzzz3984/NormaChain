add_library(peks peks.cpp peks.h)
target_link_libraries(peks PUBLIC ${OPENSSL_LIBRARIES} ${GMP_LIBRARIES} ${PBC_LIBRARIES} ${Boost_LIBRARIES} m)
