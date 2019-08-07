#########################################################################################
#	server directory
#########################################################################################

find_package(OpenSSL REQUIRED)

target_sources(${HAP_library} PRIVATE 
    HAPServer.cpp
    ControllerDevice.cpp
    EncryptedHTTPSocket.cpp
    EncryptionKeyStore.cpp
    PairingHandler.cpp )

target_link_libraries(${HAP_library} PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_subdirectory(crypto)
add_subdirectory(http)
add_subdirectory(tlv)