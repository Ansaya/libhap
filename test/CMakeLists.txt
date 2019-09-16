find_package(Catch2 CONFIG REQUIRED)
include(CTest)
include(Catch)

#########################################################################################
#	HAP library tests compile options
#########################################################################################

add_executable(HAPTests 
    test.cpp 
    AccessoryBridge.cpp
    Characteristic.cpp
    CharacteristicInternal.cpp )

set_property(TARGET HAPTests PROPERTY CXX_STANDARD 17)

target_link_libraries(HAPTests 
    PRIVATE
    Catch2::Catch2
    HAP::HAP )


#########################################################################################
#	HAP library tests subdirectories
#########################################################################################

add_subdirectory(server)

catch_discover_tests(HAPTests)