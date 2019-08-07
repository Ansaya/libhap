cmake_minimum_required(VERSION 3.13)

project(HAP)

#########################################################################################
#	Include directories
#########################################################################################

add_subdirectory(src)

if (CMAKE_BUILD_TYPE MATCHES "[Dd]ebug")
	message( STATUS "Configuring tests..." )
	add_subdirectory(test)
endif()


#########################################################################################
#   Doxygen documentation
#########################################################################################

option(BUILD_DOC "Build documentation" ON)

if (BUILD_DOC AND CMAKE_BUILD_TYPE MATCHES "[Rr]elease")
	find_package(Doxygen)
	if (DOXYGEN_FOUND)
    	configure_file(Doxyfile.in Doxyfile @ONLY)
    	message( STATUS "Configuring doxygen documentation...")

    	add_custom_target( doc_doxygen ALL
        	COMMAND Doxygen::doxygen Doxyfile
          	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
          	COMMENT "Generating API documentation with Doxygen"
          	VERBATIM )
	else()
		message( WARNING "Doxygen need to be installed to generate the doxygen documentation")
	endif()
endif()