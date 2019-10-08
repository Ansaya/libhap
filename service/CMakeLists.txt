
add_executable(HAPService service.cpp)
target_link_libraries(HAPService PRIVATE HAP::HAP)