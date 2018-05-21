add_library(agent agent.cpp agent.h)
target_include_directories(agent PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(agent PUBLIC peks contract configparser ${Boost_LIBRARIES})

add_executable(test_agent main.cpp)
target_link_libraries(test_agent agent)

