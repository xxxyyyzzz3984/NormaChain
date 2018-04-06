add_executable(Server main.cpp kdc.cpp)
target_link_libraries(Server PUBLIC ecies configparser ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
