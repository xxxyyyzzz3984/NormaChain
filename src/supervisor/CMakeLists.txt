add_library(supervisor supervisor.cpp supervisor.h)
target_include_directories(supervisor PUBLIC ${PROJECT_SOURCE_DIR}/src)
