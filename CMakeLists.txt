cmake_minimum_required(VERSION 3.16)
project(bras_collector
    VERSION     1.0.0
    LANGUAGES   CXX C
    DESCRIPTION "BRAS Full-Traffic Collector based on DPDK+PcapPlusPlus+nDPI"
)

set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Build type: Debug / Release / RelWithDebInfo" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

option(ENABLE_ASAN     "Enable AddressSanitizer (Debug only)"       OFF)
option(ENABLE_TESTS    "Build unit tests"                            OFF)
option(ENABLE_MLX5     "Enable Mellanox ConnectX-5 optimizations"   OFF)
option(ENABLE_HUGEPAGE "Add hugepage mount helper target"            ON)

find_package(PkgConfig REQUIRED)
find_package(Threads   REQUIRED)

# ── DPDK ──────────────────────────────────────────────────
pkg_check_modules(DPDK REQUIRED libdpdk)
message(STATUS "DPDK version   : ${DPDK_VERSION}")
message(STATUS "DPDK include   : ${DPDK_INCLUDE_DIRS}")

# ── PcapPlusPlus ──────────────────────────────────────────
find_package(PcapPlusPlus QUIET)
if(NOT PcapPlusPlus_FOUND)
    pkg_check_modules(PCAPPP QUIET PcapPlusPlus)
    if(NOT PCAPPP_FOUND)
        find_path(PCAPPP_INCLUDE_DIRS NAMES Packet.h
            PATHS /usr/local/include/pcapplusplus
                  /usr/include/pcapplusplus)
        find_library(PCAPPP_LIB_PCAP   NAMES Pcap++
            PATHS /usr/local/lib /usr/lib)
        find_library(PCAPPP_LIB_PACKET NAMES Packet++
            PATHS /usr/local/lib /usr/lib)
        find_library(PCAPPP_LIB_COMMON NAMES Common++
            PATHS /usr/local/lib /usr/lib)
        if(PCAPPP_INCLUDE_DIRS AND PCAPPP_LIB_PCAP)
            set(PCAPPP_LIBRARIES
                ${PCAPPP_LIB_PCAP}
                ${PCAPPP_LIB_PACKET}
                ${PCAPPP_LIB_COMMON})
            set(PCAPPP_FOUND TRUE)
        else()
            message(FATAL_ERROR "PcapPlusPlus not found.")
        endif()
    endif()
endif()

# ── nDPI ──────────────────────────────────────────────────
pkg_check_modules(NDPI QUIET libndpi)
if(NOT NDPI_FOUND)
    find_path(NDPI_INCLUDE_DIRS NAMES ndpi_main.h
        PATHS /usr/local/include/ndpi /usr/include/ndpi)
    find_library(NDPI_LIBRARIES NAMES ndpi
        PATHS /usr/local/lib /usr/lib)
    if(NDPI_INCLUDE_DIRS AND NDPI_LIBRARIES)
        set(NDPI_FOUND TRUE)
    else()
        message(FATAL_ERROR "nDPI not found.")
    endif()
endif()

# ── spdlog ────────────────────────────────────────────────
find_package(spdlog QUIET)
if(NOT spdlog_FOUND)
    pkg_check_modules(SPDLOG QUIET spdlog)
    if(NOT SPDLOG_FOUND)
        find_path(SPDLOG_INCLUDE_DIRS NAMES spdlog/spdlog.h
            PATHS /usr/local/include /usr/include)
        if(NOT SPDLOG_INCLUDE_DIRS)
            message(FATAL_ERROR "spdlog not found.")
        endif()
        set(SPDLOG_LIBRARIES "")
    endif()
endif()

# ── nlohmann/json ─────────────────────────────────────────
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    find_path(NLOHMANN_JSON_INCLUDE_DIRS NAMES nlohmann/json.hpp
        PATHS /usr/local/include /usr/include)
    if(NOT NLOHMANN_JSON_INCLUDE_DIRS)
        message(FATAL_ERROR "nlohmann/json not found.")
    endif()
endif()

find_library(PCAP_LIBRARY NAMES pcap PATHS /usr/local/lib /usr/lib)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found.")
endif()

find_library(NUMA_LIBRARY NAMES numa PATHS /usr/local/lib /usr/lib)
if(NOT NUMA_LIBRARY)
    message(WARNING "libnuma not found")
    set(NUMA_LIBRARY "")
endif()

# ─────────────────────────────────────────────────────────
# ★ 源文件收集（修正：补全所有新增 .cpp）
# ─────────────────────────────────────────────────────────
set(SOURCES_CORE
    src/core/dpdk_engine.cpp
    src/core/flow_dispatcher.cpp
    src/core/hw_flow_steering.cpp
)

set(SOURCES_PARSER
    src/parser/radius_parser.cpp
    src/parser/pppoe_parser.cpp
    src/parser/dns_parser.cpp
    src/parser/ndpi_analyzer.cpp
    src/parser/cpe_detector.cpp
    src/parser/onu_parser.cpp              # ★ 新增
)

set(SOURCES_SESSION
    src/session/flow_table.cpp
    src/session/http_session.cpp
    src/session/udp_session.cpp
    src/session/radius_session_manager.cpp # ★ 新增
)

set(SOURCES_THREADS
    src/threads/rx_thread.cpp
    src/threads/radius_thread.cpp
    src/threads/worker_thread.cpp
    src/threads/output_thread.cpp
    src/threads/monitor_thread.cpp
)

set(SOURCES_OUTPUT
    src/output/dcs_writer.cpp
    src/output/raw_file_manager.cpp
    src/output/http_dcs_serializer.cpp
    src/output/radius_dcs_serializer.cpp   # ★ 新增
    src/output/onu_dcs_serializer.cpp      # ★ 新增
)

set(SOURCES_UTILS
    src/utils/logger.cpp
    src/utils/config.cpp
    src/utils/stats.cpp
)

set(SOURCES_ALL
    src/main.cpp
    ${SOURCES_CORE}
    ${SOURCES_PARSER}
    ${SOURCES_SESSION}
    ${SOURCES_THREADS}
    ${SOURCES_OUTPUT}
    ${SOURCES_UTILS}
)

add_executable(collector ${SOURCES_ALL})

target_include_directories(collector
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${DPDK_INCLUDE_DIRS}
        ${PCAPPP_INCLUDE_DIRS}
        ${NDPI_INCLUDE_DIRS}
        ${SPDLOG_INCLUDE_DIRS}
        ${NLOHMANN_JSON_INCLUDE_DIRS}
)

target_compile_options(collector
    PRIVATE
        -Wall -Wextra
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        $<$<CONFIG:Release>:-O3 -march=native -DNDEBUG>
        $<$<CONFIG:Debug>:-O0 -g3 -fno-omit-frame-pointer>
        $<$<CONFIG:RelWithDebInfo>:-O2 -g -march=native>
        ${DPDK_CFLAGS_OTHER}
)

if(ENABLE_ASAN AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(collector PRIVATE
        -fsanitize=address -fsanitize=undefined
        -fno-sanitize-recover=all)
    target_link_options(collector PRIVATE
        -fsanitize=address -fsanitize=undefined)
endif()

if(ENABLE_MLX5)
    target_compile_definitions(collector PRIVATE
        ENABLE_MLX5_OPT=1 RTE_LIBRTE_MLX5_PMD=1)
endif()

target_compile_definitions(collector
    PRIVATE
        ALLOW_EXPERIMENTAL_API
        COLLECTOR_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        COLLECTOR_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        COLLECTOR_VERSION_PATCH=${PROJECT_VERSION_PATCH}
        SPDLOG_FMT_EXTERNAL=0
        PCAPPP_DISABLE_DEBUG_LOGGING
)

set(DPDK_WHOLE_ARCHIVE_LIBS "")
set(DPDK_NORMAL_LIBS "")
foreach(lib ${DPDK_LIBRARIES})
    if(lib MATCHES "rte_pmd|rte_bus|rte_mempool|rte_net")
        list(APPEND DPDK_WHOLE_ARCHIVE_LIBS ${lib})
    else()
        list(APPEND DPDK_NORMAL_LIBS ${lib})
    endif()
endforeach()

target_link_libraries(collector
    PRIVATE
        -Wl,--whole-archive
        ${DPDK_WHOLE_ARCHIVE_LIBS}
        -Wl,--no-whole-archive
        ${DPDK_NORMAL_LIBS}
        ${PCAPPP_LIBRARIES}
        ${PCAP_LIBRARY}
        ${NDPI_LIBRARIES}
        $<$<BOOL:${SPDLOG_LIBRARIES}>:${SPDLOG_LIBRARIES}>
        $<$<TARGET_EXISTS:nlohmann_json::nlohmann_json>:nlohmann_json::nlohmann_json>
        Threads::Threads
        ${NUMA_LIBRARY}
        dl rt m
)

if(ENABLE_MLX5)
    target_link_libraries(collector PRIVATE mlx5 ibverbs mnl)
endif()

target_link_options(collector PRIVATE -rdynamic -Wl,--export-dynamic)

# ─────────────────────────────────────────────────────────
# ★ 单元测试（补全所有新增测试文件）
# ─────────────────────────────────────────────────────────
if(ENABLE_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)

    set(TEST_SOURCES
        tests/test_http_serializer.cpp
        tests/test_flow_table.cpp
        tests/test_radius_parser.cpp
        tests/test_radius_serializer.cpp   # ★ 新增
        tests/test_dns_parser.cpp
        tests/test_cpe_detector.cpp
        tests/test_rtt_tracker.cpp
        tests/test_loss_detector.cpp
        tests/test_lock_free_queue.cpp     # ★ 新增
        tests/test_onu_serializer.cpp      # ★ 新增
    )

    add_executable(collector_tests ${TEST_SOURCES}
        ${SOURCES_CORE}
        ${SOURCES_PARSER}
        ${SOURCES_SESSION}
        ${SOURCES_OUTPUT}
        ${SOURCES_UTILS}
    )

    target_include_directories(collector_tests
        PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src
            ${DPDK_INCLUDE_DIRS}
            ${PCAPPP_INCLUDE_DIRS}
            ${NDPI_INCLUDE_DIRS}
            ${SPDLOG_INCLUDE_DIRS}
            ${NLOHMANN_JSON_INCLUDE_DIRS}
            ${GTEST_INCLUDE_DIRS}
    )

    target_compile_definitions(collector_tests
        PRIVATE
            ALLOW_EXPERIMENTAL_API
            UNIT_TEST_BUILD
    )

    target_link_libraries(collector_tests
        PRIVATE
            GTest::GTest GTest::Main
            -Wl,--whole-archive
            ${DPDK_WHOLE_ARCHIVE_LIBS}
            -Wl,--no-whole-archive
            ${DPDK_NORMAL_LIBS}
            ${PCAPPP_LIBRARIES} ${PCAP_LIBRARY}
            ${NDPI_LIBRARIES}
            Threads::Threads ${NUMA_LIBRARY}
            dl rt m
    )

    include(GoogleTest)
    gtest_discover_tests(collector_tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        TIMEOUT 30
    )
    message(STATUS "Unit tests enabled")
endif()

install(TARGETS collector RUNTIME DESTINATION bin)
install(DIRECTORY config/
    DESTINATION etc/collector
    FILES_MATCHING PATTERN "*.json")
install(DIRECTORY scripts/
    DESTINATION share/collector/scripts
    FILES_MATCHING PATTERN "*.sh"
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                GROUP_EXECUTE GROUP_READ)

if(ENABLE_HUGEPAGE)
    add_custom_target(setup_hugepages
        COMMAND ${CMAKE_SOURCE_DIR}/scripts/setup_hugepages.sh
        COMMENT "Setting up hugepages for DPDK"
        VERBATIM)
endif()

message(STATUS "")
message(STATUS "══════════════════════════════════════════")
message(STATUS "  bras_collector ${PROJECT_VERSION} configuration")
message(STATUS "══════════════════════════════════════════")
message(STATUS "  Build type    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard  : ${CMAKE_CXX_STANDARD}")
message(STATUS "  DPDK          : ${DPDK_VERSION}")
message(STATUS "  ConnectX-5    : ${ENABLE_MLX5}")
message(STATUS "  ASan          : ${ENABLE_ASAN}")
message(STATUS "  Tests         : ${ENABLE_TESTS}")
message(STATUS "══════════════════════════════════════════")
message(STATUS "")
