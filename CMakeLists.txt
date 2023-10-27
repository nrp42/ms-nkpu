cmake_minimum_required(VERSION 3.5.0)
project(ms-nkpu VERSION 0.1.0)

find_package(OpenSSL REQUIRED)

add_library(ms-nkpu SHARED
    "ms-nkpu-hooks.cpp"
    "ms-nkpu.cpp"
    "ms-nkpu-msgs.cpp"
    "ms-nkpu-log.cpp"
)

target_include_directories(ms-nkpu PRIVATE
    /usr/include/kea
)
