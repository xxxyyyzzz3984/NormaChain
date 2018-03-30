add_library(eccverify eccverify.cpp)
target_include_directories(eccverify PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(eccverify PUBLIC ecies)
