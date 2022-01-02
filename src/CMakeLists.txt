cmake_minimum_required(VERSION 3.10)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_CXX_STANDARD 17)
set(COMPILER_FLAGS "-O3 -Wall --std=c++17 -march=native -funroll-loops -fconstexpr-steps=8388608")
#set(COMPILER_FLAGS "-O3 -Wall --std=c++17 -march=skylake -funroll-loops -fconstexpr-steps=16777216")
set(LINKER_FLAGS "-static-libstdc++ -static-libgcc")
set(CMAKE_CXX_FLAGS "${COMPILER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LINKER_FLAGS}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_subdirectory(crypto)

include_directories(${CMAKE_CURRENT_LIST_DIR}/crypto)

add_executable(wem3 WEM3.cpp)
target_link_libraries(wem3 WEM2EM GF28 COMPONENT)

add_executable(wem4 WEM4.cpp)
target_link_libraries(wem4 COMPONENT)

add_executable(bench1 bench1.cpp)
target_link_libraries(bench1 COMPONENT)

add_executable(bench2 bench2.cpp)
target_link_libraries(bench2 COMPONENT)

