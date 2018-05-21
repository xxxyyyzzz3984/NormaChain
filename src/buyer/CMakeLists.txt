add_library(buyer buyer.cpp buyer.h)
target_link_libraries(buyer PUBLIC configparser contract seller approver ${Boost_LIBRARIES})

add_executable(test_buyer main.cpp)
target_link_libraries(test_buyer buyer)
