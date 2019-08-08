#########################################################################################
#	dns_sd directory
#########################################################################################

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
include(FindDNSSD)
find_package(DNSSD REQUIRED)

target_sources(${HAP_library} PRIVATE 
    TXTRecord.cpp )

target_include_directories(${HAP_library}
    PRIVATE
    ${DNSSD_INCLUDE_DIRS})

target_link_libraries(${HAP_library} 
    PRIVATE
    ${DNSSD_LIBRARIES} )