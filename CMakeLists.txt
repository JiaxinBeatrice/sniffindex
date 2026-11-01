cmake_minimum_required(VERSION 3.16)
project(sniffindex CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

# One exe that runs on any Windows, without the Visual C++ runtime installed
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

add_executable(sniffindex sniffindex.cpp)

enable_testing()

file(GLOB captures CONFIGURE_DEPENDS tests/data/*.pcap tests/data/*.pcapng)
foreach(capture ${captures})
    get_filename_component(name ${capture} NAME)
    add_test(
        NAME tshark_answer_${name}
        COMMAND ${CMAKE_COMMAND}
            -DSNIFFINDEX=$<TARGET_FILE:sniffindex>
            -DCAPTURE=${capture}
            -DWORK=${CMAKE_CURRENT_BINARY_DIR}/test_output
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/compare.cmake
    )
endforeach()

add_test(
    NAME path_with_special_characters
    COMMAND ${CMAKE_COMMAND}
        -DSNIFFINDEX=$<TARGET_FILE:sniffindex>
        -DCAPTURE=${CMAKE_CURRENT_SOURCE_DIR}/tests/data/radiotap.pcap
        "-DPATH_NAME=問題 A,log(1)&%.pcap"
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/test_output
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/compare.cmake
)

add_test(
    NAME unsupported_input_is_an_error
    COMMAND ${CMAKE_COMMAND}
        -DSNIFFINDEX=$<TARGET_FILE:sniffindex>
        -DSOURCE_FOLDER=${CMAKE_CURRENT_SOURCE_DIR}
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/test_output
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/errors.cmake
)
