# SQLite3 Amalgamation Build
set(LIBNAME sqlite3)

message(STATUS "[src/${LIBNAME}] Module Processing...")

# SQLite3 amalgamation dosyalarını kontrol et
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sqlite3.c")
    message(FATAL_ERROR "SQLite3 amalgamation files not found! Please run download-sqlite.bat or manually download sqlite3.c and sqlite3.h from https://www.sqlite.org/download.html")
endif()

# SQLite3 kaynak dosyaları
set(SQLITE3_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/sqlite3.c
)

set(SQLITE3_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/sqlite3.h
)

# Static library oluştur
add_library(${LIBNAME} STATIC ${SQLITE3_SOURCES} ${SQLITE3_HEADERS})

# Public include directory
target_include_directories(${LIBNAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Windows için threading desteği ve runtime library
if(WIN32)
    target_compile_definitions(${LIBNAME} PRIVATE 
        SQLITE_THREADSAFE=1
        SQLITE_ENABLE_COLUMN_METADATA
        SQLITE_ENABLE_FTS5
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_WARNINGS
    )
    
    # Windows runtime libraries
    if(MSVC)
        # Use /MD for DLL runtime (required for __imp_ symbols)
        set_target_properties(${LIBNAME} PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        )
        
        # Add compile options for SQLite3
        target_compile_options(${LIBNAME} PRIVATE
            /wd4996  # Disable deprecated warnings
        )
    endif()
    
    # Link against Windows libraries
    target_link_libraries(${LIBNAME} PUBLIC
        kernel32
        advapi32
        user32
    )
endif()

# Install hedefleri
install(TARGETS ${LIBNAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/sqlite3.h
        DESTINATION include)

message(STATUS "[src/${LIBNAME}] SQLite3 static library configured")

