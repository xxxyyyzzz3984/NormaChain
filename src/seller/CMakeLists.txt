add_library(seller seller.cpp seller.h)
target_include_directories(seller PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(seller ${Boost_LIBRARIES} configparser)

add_executable(test_seller main.cpp)
target_include_directories(test_seller PUBLIC ${PROJECT_SOURCE_DIR}/src configparser contract seller)
target_link_libraries(test_seller seller)
