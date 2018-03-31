add_executable(Verifier main.cpp verifier.cpp)
target_link_libraries(Verifier PUBLIC ecies configparser ${BOOST_LIBS} ${CMAKE_THREAD_LIBS_INIT})
