# Set the minimum required CMake version
cmake_minimum_required(VERSION 3.12)
project(personalapp)

set(ROOT src)

# Print useful information
message(STATUS "[${ROOT}] CMake version ${CMAKE_VERSION}")
message(STATUS "[${ROOT}] System ${CMAKE_SYSTEM_NAME}")
message(STATUS "[${ROOT}] Processor ${CMAKE_SYSTEM_PROCESSOR}")

# GoogleTest requires at least C++11
if(NOT "${CMAKE_CXX_STANDARD}")
  set(CMAKE_CXX_STANDARD 11)
  message(STATUS "[${ROOT}] Default C++ Standard Selected: ${CMAKE_CXX_STANDARD}")
endif()

message(STATUS "[${ROOT}] C++ standard version: ${CMAKE_CXX_STANDARD}")

# Set the default installation directory
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/install" CACHE PATH "Default installation directory" FORCE)
endif()

message(STATUS "[${ROOT}] Folder is set to : ${CMAKE_INSTALL_PREFIX}")

set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable testing
enable_testing()

# Set build configurations
set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)

#crypto++ settings, disable testing, documentation generation, install and DLL generation
set(CRYPTOPP_BUILD_TESTING OFF)
set(CRYPTOPP_BUILD_DOCUMENTATION OFF)
set(CRYPTOPP_INSTALL ON)
set(CRYPTOPP_BUILD_SHARED OFF)
set(CRYPTOPP_USE_MASTER_BRANCH FALSE)

option(ENABLE_UTILITY "Enable Utility Module" ON)
option(ENABLE_personal "Enable personal Module" ON)
option(ENABLE_personal_APP "Enable personal Application" ON)
option(ENABLE_TESTS "Enable All Tests" ON)

# SQLite3 dependency
find_package(SQLite3)
if(NOT SQLite3_FOUND)
    message(STATUS "SQLite3 not found via find_package, using amalgamation")
    set(SQLITE3_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/src/sqlite3")
    set(SQLITE3_LIBRARY "sqlite3")
    set(USE_SQLITE3_AMALGAMATION ON)
endif()

# GoogleTest Runtime Library (must match project settings)
if(MSVC)
    set(gtest_force_shared_crt OFF CACHE BOOL "Use shared (DLL) run-time lib even when Google Test is built as static lib." FORCE)
endif()

# Configure tests
add_compile_definitions(ENABLE_UTILITY_TEST)
add_compile_definitions(ENABLE_personal_TEST)


# Configure logs
add_compile_definitions(ENABLE_UTILITY_LOGGER)
add_compile_definitions(ENABLE_personal_LOGGER)

# Set the output directories for Debug and Release configurations
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/build/Debug)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/build/Release)

# Custom definitions based on environment
if(MSVC)
  add_definitions(-DMSVC_ENV)
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
  add_definitions(-DGCC_ENV)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_definitions(-DMAC_ENV)
endif()

# Set Debug and Release configuration flags
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  message(STATUS "[${ROOT}] Setting Ubuntu/MacOS C/C++ Flags")

  set(COMP_WARNINGS "-Wall -Wextra -Wunused-function -Wno-unknown-pragmas")
  set(COMP_PROFILE "-fprofile-arcs -ftest-coverage")
  set(COMP_OPTIMIZATION "-O0") #for debugging
  set(COMP_SHARED "-shared -fPIC")

  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g ${COMP_OPTIMIZATION} ${COMP_WARNINGS} ${COMP_PROFILE}")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g ${COMP_OPTIMIZATION} ${COMP_WARNINGS} ${COMP_PROFILE}")

  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} ${COMP_WARNINGS} ${COMP_PROFILE}")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${COMP_WARNINGS} ${COMP_PROFILE}")

elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  message(STATUS "[${ROOT}] Setting Windows C/C++ Flags")
  
  # Global MSVC Runtime Library Policy - Use DLL runtime for compatibility
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MDd")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MD")
else()
  message(WARNING "[${ROOT}] Not supported with the current compiler.")
endif()



# SQLite3 submodule (if using amalgamation)
if(USE_SQLITE3_AMALGAMATION)
	add_subdirectory(${ROOT}/sqlite3)
endif()

# Utility submodule
if(ENABLE_UTILITY)
	add_subdirectory(${ROOT}/utility)
endif()

# Logger submodule
if(ENABLE_personal)
	add_subdirectory(${ROOT}/personal)
endif()

# BigInteger for Crypto submodule
if(ENABLE_personal_APP)
	add_subdirectory(${ROOT}/personalapp)
endif()

# Tests
if(ENABLE_TESTS)
	add_subdirectory(${ROOT}/tests)
endif()

# Include the Google Test framework
# add_subdirectory(src/tests/googletest)


