add_library(buyer buyer.cpp buyer.h)
target_include_directories(buyer PUBLIC ${PROJECT_SOURCE_DIR}/src configparser contract seller)
target_link_libraries(buyer PUBLIC configparser contract seller ${Boost_LIBRARIES})

add_executable(test_buyer main.cpp)
target_include_directories(test_buyer PUBLIC ${PROJECT_SOURCE_DIR}/src configparser contract seller)
target_link_libraries(test_buyer buyer)
