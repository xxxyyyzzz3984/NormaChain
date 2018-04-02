add_executable(Verifier main.cpp verifier.cpp)
target_link_libraries(Verifier PUBLIC ecies configparser ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
