#########################################################################################
#	crypto directory
#########################################################################################

find_package(OpenSSL REQUIRED)

target_sources(HAPTests PRIVATE
    ChaCha20Poly1305.cpp
    Ed25519.cpp
    SRP.cpp )

target_link_libraries(HAPTests PRIVATE OpenSSL::SSL)