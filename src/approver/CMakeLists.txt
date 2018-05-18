add_library(approver approver.cpp approver.h)
target_include_directories(approver PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(approver configparser contract)

add_executable(test_approver main.cpp)
target_include_directories(test_approver PUBLIC ${PROJECT_SOURCE_DIR}/src configparser contract seller)
target_link_libraries(test_approver approver)
