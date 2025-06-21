cmake_minimum_required(VERSION 3.8)

set(CMAKE_C_COMPILER "C:/Program Files/LLVM/bin/clang.exe")
set(CMAKE_CXX_COMPILER "C:/Program Files/LLVM/bin/clang++.exe")

project("SteamClientLoader")

add_library(SteamClientLoader SHARED "SteamClientLoader.cpp")

set_target_properties(SteamClientLoader PROPERTIES
    OUTPUT_NAME "version"
    SUFFIX ".dll"
    PREFIX ""
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
    set_property(TARGET SteamClientLoader PROPERTY CXX_STANDARD 20)
endif()

if(WIN32)
    target_link_libraries(SteamClientLoader
        kernel32
        user32
        advapi32
        winmm
        version
    )
    
    target_compile_definitions(SteamClientLoader PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0601
    )
    
    target_link_options(SteamClientLoader PRIVATE
    )
endif()

target_compile_options(SteamClientLoader PRIVATE
    -Wall
    -Wextra
    -O2

)