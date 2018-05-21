add_library(seller seller.cpp seller.h)
target_link_libraries(seller ${Boost_LIBRARIES} configparser)

add_executable(test_seller main.cpp)
target_link_libraries(test_seller seller)
