find_package(Threads REQUIRED)
find_package(RapidJSON CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

include(CheckIPOSupported)
include(GenerateExportHeader)

set(HAP_library "HAP")

# Relative paths are converted to absolute
cmake_policy(SET CMP0076 NEW)

# Link libraries to target from different directory
cmake_policy(SET CMP0079 NEW)

#########################################################################################
#	HAP library compiler options
#########################################################################################

add_library(${HAP_library} SHARED 
    Accessory.cpp
    AccessoryBridge.cpp
    AccessoryInternal.cpp
    Characteristic.cpp
    CharacteristicFormat.cpp
    CharacteristicInternal.cpp
    CharacteristicPermission.cpp
    CharacteristicUnit.cpp
    log.cpp 
    PrimaryAccessory.cpp
    PrimaryAccessoryInternal.cpp
    Service.cpp
    ServiceInternal.cpp )

add_library(${PROJECT_NAME}::${HAP_library} ALIAS ${HAP_library})

generate_export_header(${HAP_library} EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/hap_export.h)

target_include_directories(${HAP_library} 
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/hap>
    $<$<CONFIG:Debug>:${CMAKE_CURRENT_SOURCE_DIR}/private_include>
    $<$<CONFIG:Debug>:${CMAKE_CURRENT_BINARY_DIR}/private_include>
    
    INTERFACE
    ${RapidJSON_INCLUDES} 
    
    PRIVATE
    $<$<CONFIG:Release>:${CMAKE_CURRENT_SOURCE_DIR}/private_include>
    $<$<CONFIG:Release>:${CMAKE_CURRENT_BINARY_DIR}/private_include> )

target_link_libraries(${HAP_library}
    PUBLIC
    Threads::Threads

    PRIVATE
    spdlog::spdlog )

set_property(TARGET ${HAP_library} PROPERTY CXX_STANDARD 17)

if(CMAKE_BUILD_TYPE MATCHES "[Rr]elease")
    set_property(TARGET ${HAP_library} PROPERTY CMAKE_CXX_VISIBILITY hidden)
    set_property(TARGET ${HAP_library} PROPERTY CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()

target_compile_options(${HAP_library}
    PUBLIC 
    "-fexceptions"
        
    PRIVATE 
    $<$<CONFIG:Debug>:-Wall> 
    $<IF:$<CONFIG:DEBUG>,-O0,-O3>
        
    $<$<CONFIG:Debug>:-g2> 
    $<$<CONFIG:Debug>:-gdwarf-2> 
    $<$<CONFIG:Debug>:--coverage> 
    $<$<CONFIG:Debug>:-fprofile-arcs> 
    $<$<CONFIG:Debug>:-ftest-coverage> 

    $<$<NOT:$<CONFIG:Debug>>:-march=native> 
    $<$<NOT:$<CONFIG:Debug>>:-fomit-frame-pointer> 
    $<$<NOT:$<CONFIG:Debug>>:-fopt-info> 
    $<$<NOT:$<CONFIG:Debug>>:-ffast-math> )

# Optional LTO. Do not use LTO if it's not supported by compiler.
check_ipo_supported(RESULT result OUTPUT output)
if(result)
  set_property(TARGET ${HAP_library} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
  message( WARNING "LTO is not supported: ${output}" )
endif()


#########################################################################################
#	Subdirectory objects inclusion
#########################################################################################

add_subdirectory(server)


#########################################################################################
#	Code coverage custom target
#########################################################################################

if (CMAKE_BUILD_TYPE MATCHES "^[Dd]ebug")
    if(CMAKE_COMPILER_IS_GNUCXX)
        set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/test)
        include(CodeCoverage)
        APPEND_COVERAGE_COMPILER_FLAGS()
        set(COVERAGE_LCOV_EXCLUDES '/usr/*')
        SETUP_TARGET_FOR_COVERAGE_LCOV(NAME CodeCoverage 
            EXECUTABLE ${PROJECT_BINARY_DIR}/test/HAPTests
            DEPENDENCIES HAPTests)
    endif()
endif()


#########################################################################################
#	HAP library installation
#########################################################################################

install(TARGETS ${HAP_library}
    EXPORT ${PROJECT_NAME}
    LIBRARY
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
        COMPONENT SharedLibrary
    ARCHIVE
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/static
        COMPONENT StaticLibrary )

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ ${CMAKE_BINARY_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/hap
    COMPONENT Development )