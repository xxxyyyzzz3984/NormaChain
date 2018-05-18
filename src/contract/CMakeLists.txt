add_library(contract contract.cpp)
target_include_directories(contract PUBLIC ${PROJECT_SOURCE_DIR}/src configparser)
target_link_libraries(contract ${Boost_LIBRARIES} configparser)
