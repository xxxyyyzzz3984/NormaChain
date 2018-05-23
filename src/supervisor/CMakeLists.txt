add_library(supervisor supervisor.cpp supervisor.h)
target_link_libraries(supervisor configparser agent ${Boost_LIBRARIES})

add_executable(test_supervisor main.cpp)
target_link_libraries(test_supervisor supervisor)
