add_executable(Proofer main.cpp proofer.cpp)
target_link_libraries(Proofer PUBLIC ecies configparser ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
