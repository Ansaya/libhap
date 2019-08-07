#########################################################################################
#	crypto directory
#########################################################################################

find_package(OpenSSL REQUIRED)

target_sources(${HAP_library} PRIVATE 
    ChaCha20Poly1305.cpp
    Ed25519.cpp
    HKDF.cpp
    SRP.cpp )

target_link_libraries(${HAP_library} 
    PRIVATE
    OpenSSL::SSL 
    OpenSSL::Crypto )