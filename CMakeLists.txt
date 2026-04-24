cmake_minimum_required(VERSION 3.16)
project(bras_collector
    VERSION     1.0.0
    LANGUAGES   CXX C
    DESCRIPTION "BRAS Full-Traffic Collector based on DPDK+PcapPlusPlus+nDPI"
)

# ─────────────────────────────────────────────────────────
# C++ 标准
# ─────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ─────────────────────────────────────────────────────────
# 构建类型默认 Release
# ─────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Build type: Debug / Release / RelWithDebInfo" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# ─────────────────────────────────────────────────────────
# 选项开关
# ─────────────────────────────────────────────────────────
option(ENABLE_ASAN       "Enable AddressSanitizer (Debug only)"  OFF)
option(ENABLE_TESTS      "Build unit tests"                       OFF)
option(ENABLE_MLX5       "Enable Mellanox ConnectX-5 optimizations" OFF)
option(ENABLE_HUGEPAGE   "Add hugepage mount helper target"       ON)

# ─────────────────────────────────────────────────────────
# 依赖查找工具
# ─────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
find_package(Threads   REQUIRED)

# ── DPDK ──────────────────────────────────────────────────
# 优先用 pkg-config，其次用 FindDPDK 模块
pkg_check_modules(DPDK REQUIRED libdpdk)
if(NOT DPDK_FOUND)
    message(FATAL_ERROR
        "DPDK not found. Install DPDK and set PKG_CONFIG_PATH.\n"
        "  Example: export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig")
endif()
message(STATUS "DPDK version   : ${DPDK_VERSION}")
message(STATUS "DPDK include   : ${DPDK_INCLUDE_DIRS}")
message(STATUS "DPDK libraries : ${DPDK_LIBRARIES}")

# ── PcapPlusPlus ──────────────────────────────────────────
find_package(PcapPlusPlus QUIET)
if(NOT PcapPlusPlus_FOUND)
    # 回退到 pkg-config
    pkg_check_modules(PCAPPP QUIET PcapPlusPlus)
    if(NOT PCAPPP_FOUND)
        # 手动查找（常见安装路径）
        find_path(PCAPPP_INCLUDE_DIRS
            NAMES Packet.h
            PATHS
                /usr/local/include/pcapplusplus
                /usr/include/pcapplusplus
                /opt/pcapplusplus/include
        )
        find_library(PCAPPP_LIB_PCAP   NAMES Pcap++
            PATHS /usr/local/lib /usr/lib /opt/pcapplusplus/lib)
        find_library(PCAPPP_LIB_PACKET NAMES Packet++
            PATHS /usr/local/lib /usr/lib /opt/pcapplusplus/lib)
        find_library(PCAPPP_LIB_COMMON NAMES Common++
            PATHS /usr/local/lib /usr/lib /opt/pcapplusplus/lib)

        if(PCAPPP_INCLUDE_DIRS AND PCAPPP_LIB_PCAP)
            set(PCAPPP_LIBRARIES
                ${PCAPPP_LIB_PCAP}
                ${PCAPPP_LIB_PACKET}
                ${PCAPPP_LIB_COMMON})
            set(PCAPPP_FOUND TRUE)
        else()
            message(FATAL_ERROR
                "PcapPlusPlus not found.\n"
                "  Build from source: https://github.com/seladb/PcapPlusPlus\n"
                "  Or: apt install libpcapplusplus-dev")
        endif()
    endif()
endif()
message(STATUS "PcapPlusPlus include: ${PCAPPP_INCLUDE_DIRS}")
message(STATUS "PcapPlusPlus libs   : ${PCAPPP_LIBRARIES}")

# ── nDPI ──────────────────────────────────────────────────
pkg_check_modules(NDPI QUIET libndpi)
if(NOT NDPI_FOUND)
    find_path(NDPI_INCLUDE_DIRS
        NAMES ndpi_main.h
        PATHS
            /usr/local/include/ndpi
            /usr/include/ndpi
            /opt/ndpi/include
    )
    find_library(NDPI_LIBRARIES NAMES ndpi
        PATHS /usr/local/lib /usr/lib /opt/ndpi/lib)
    if(NDPI_INCLUDE_DIRS AND NDPI_LIBRARIES)
        set(NDPI_FOUND TRUE)
    else()
        message(FATAL_ERROR
            "nDPI not found.\n"
            "  Build from source: https://github.com/ntop/nDPI\n"
            "  Or: apt install libndpi-dev")
    endif()
endif()
message(STATUS "nDPI include: ${NDPI_INCLUDE_DIRS}")
message(STATUS "nDPI libs   : ${NDPI_LIBRARIES}")

# ── spdlog ────────────────────────────────────────────────
find_package(spdlog QUIET)
if(NOT spdlog_FOUND)
    pkg_check_modules(SPDLOG QUIET spdlog)
    if(NOT SPDLOG_FOUND)
        # header-only 模式：只需找头文件
        find_path(SPDLOG_INCLUDE_DIRS
            NAMES spdlog/spdlog.h
            PATHS
                /usr/local/include
                /usr/include
        )
        if(NOT SPDLOG_INCLUDE_DIRS)
            message(FATAL_ERROR
                "spdlog not found.\n"
                "  apt install libspdlog-dev\n"
                "  Or: vcpkg install spdlog")
        endif()
        set(SPDLOG_FOUND TRUE)
        set(SPDLOG_LIBRARIES "")   # header-only，无需链接库
    endif()
endif()
message(STATUS "spdlog include: ${SPDLOG_INCLUDE_DIRS}")

# ── nlohmann/json（配置文件解析）─────────────────────────
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    find_path(NLOHMANN_JSON_INCLUDE_DIRS
        NAMES nlohmann/json.hpp
        PATHS
            /usr/local/include
            /usr/include
    )
    if(NOT NLOHMANN_JSON_INCLUDE_DIRS)
        message(FATAL_ERROR
            "nlohmann/json not found.\n"
            "  apt install nlohmann-json3-dev\n"
            "  Or: vcpkg install nlohmann-json")
    endif()
endif()
message(STATUS "nlohmann/json found")

# ── libpcap（PcapPlusPlus 依赖）──────────────────────────
find_library(PCAP_LIBRARY NAMES pcap
    PATHS /usr/local/lib /usr/lib)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR
        "libpcap not found.\n"
        "  apt install libpcap-dev")
endif()

# ── libnuma（DPDK NUMA支持）──────────────────────────────
find_library(NUMA_LIBRARY NAMES numa
    PATHS /usr/local/lib /usr/lib)
if(NOT NUMA_LIBRARY)
    message(WARNING "libnuma not found, NUMA optimizations disabled")
    set(NUMA_LIBRARY "")
endif()

# ─────────────────────────────────────────────────────────
# 源文件收集
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
)

set(SOURCES_SESSION
    src/session/flow_table.cpp
    src/session/http_session.cpp
    src/session/udp_session.cpp
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

# ─────────────────────────────────────────────────────────
# 可执行目标
# ─────────────────────────────────────────────────────────
add_executable(collector ${SOURCES_ALL})

# ─────────────────────────────────────────────────────────
# 头文件搜索路径
# ─────────────────────────────────────────────────────────
target_include_directories(collector
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include          # common.h
        ${CMAKE_SOURCE_DIR}/src              # 内部头文件
        ${DPDK_INCLUDE_DIRS}
        ${PCAPPP_INCLUDE_DIRS}
        ${NDPI_INCLUDE_DIRS}
        ${SPDLOG_INCLUDE_DIRS}
        ${NLOHMANN_JSON_INCLUDE_DIRS}
)

# ─────────────────────────────────────────────────────────
# 编译选项
# ──��──────────────────────────────────────────────────────
target_compile_options(collector
    PRIVATE
        # 通用优化
        -Wall
        -Wextra
        -Wno-unused-parameter        # DPDK回调参数经常不用
        -Wno-missing-field-initializers

        # Release 优化
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>   # 针对当前CPU优化
        $<$<CONFIG:Release>:-DNDEBUG>

        # Debug 选项
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Debug>:-fno-omit-frame-pointer>

        # RelWithDebInfo
        $<$<CONFIG:RelWithDebInfo>:-O2>
        $<$<CONFIG:RelWithDebInfo>:-g>
        $<$<CONFIG:RelWithDebInfo>:-march=native>

        # DPDK 相关编译标志（从 pkg-config 获取）
        ${DPDK_CFLAGS_OTHER}
)

# ── AddressSanitizer（Debug调试用）────────────────────────
if(ENABLE_ASAN AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(collector PRIVATE
        -fsanitize=address
        -fsanitize=undefined
        -fno-sanitize-recover=all
    )
    target_link_options(collector PRIVATE
        -fsanitize=address
        -fsanitize=undefined
    )
    message(STATUS "ASan/UBSan enabled")
endif()

# ── ConnectX-5 专项优化 ───────────────────────────────────
if(ENABLE_MLX5)
    target_compile_definitions(collector PRIVATE
        ENABLE_MLX5_OPT=1
        RTE_LIBRTE_MLX5_PMD=1
    )
    message(STATUS "ConnectX-5 (mlx5) optimizations enabled")
endif()

# ─────────────────────────────────────────────────────────
# 编译宏定义
# ─────────────────────────────────────────────────────────
target_compile_definitions(collector
    PRIVATE
        # DPDK 实验性 API（rte_flow 等需要）
        ALLOW_EXPERIMENTAL_API

        # 版本信息
        COLLECTOR_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        COLLECTOR_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        COLLECTOR_VERSION_PATCH=${PROJECT_VERSION_PATCH}

        # spdlog：使用 fmt 格式化（性能更好）
        SPDLOG_FMT_EXTERNAL=0

        # 关闭 PcapPlusPlus 调试输出
        PCAPPP_DISABLE_DEBUG_LOGGING
)

# ─────────────────────────────────────────────────────────
# 链接库
# ─────────────────────────────────────────────────────────

# 整理 DPDK 库列表：
# DPDK 使用 --whole-archive 确保所有 PMD 驱动被链接进来
# （否则运行时找不到网卡驱动）
set(DPDK_WHOLE_ARCHIVE_LIBS "")
set(DPDK_NORMAL_LIBS "")
foreach(lib ${DPDK_LIBRARIES})
    # rte_pmd_* 是 PMD 驱动，需要 whole-archive
    if(lib MATCHES "rte_pmd|rte_bus|rte_mempool|rte_net")
        list(APPEND DPDK_WHOLE_ARCHIVE_LIBS ${lib})
    else()
        list(APPEND DPDK_NORMAL_LIBS ${lib})
    endif()
endforeach()

target_link_libraries(collector
    PRIVATE
        # ── DPDK（PMD驱动用 whole-archive）──────────────
        -Wl,--whole-archive
        ${DPDK_WHOLE_ARCHIVE_LIBS}
        -Wl,--no-whole-archive
        ${DPDK_NORMAL_LIBS}

        # ── PcapPlusPlus ─────────────────────────────────
        ${PCAPPP_LIBRARIES}
        ${PCAP_LIBRARY}               # libpcap（PcapPlusPlus底层依赖）

        # ── nDPI ─────────────────────────────────────────
        ${NDPI_LIBRARIES}

        # ── spdlog（如果是编译版本而非 header-only）──────
        $<$<BOOL:${SPDLOG_LIBRARIES}>:${SPDLOG_LIBRARIES}>

        # ── nlohmann/json（header-only，无需链接）────────
        $<$<TARGET_EXISTS:nlohmann_json::nlohmann_json>:nlohmann_json::nlohmann_json>

        # ── 系统库 ───────────────────────────────────────
        Threads::Threads
        ${NUMA_LIBRARY}               # NUMA支持
        dl                            # dlopen（DPDK插件加载）
        rt                            # clock_gettime
        m                             # 数学库（nDPI用）
)

# ── mlx5 驱动额外链接 ─────────────────────────────────────
if(ENABLE_MLX5)
    target_link_libraries(collector
        PRIVATE
            mlx5           # Mellanox mlx5 用户态驱动
            ibverbs        # InfiniBand verbs
            mnl            # Netlink（mlx5依赖）
    )
endif()

# ─────────────────────────────────────────────────────────
# 链接选项
# ─────────────────────────────────────────────────────────
target_link_options(collector
    PRIVATE
        # 导出所有符号（DPDK插件机制需要）
        -rdynamic

        # 确保 DPDK 静态库的全局构造函数被执行
        -Wl,--export-dynamic
)

# ───────────────────────────────────────────────────────���─
# 单元测试
# ─────────────────────────────────────────────────────────
if(ENABLE_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)

    # 测试源文件
    set(TEST_SOURCES
        tests/test_http_serializer.cpp
        tests/test_flow_table.cpp
        tests/test_radius_parser.cpp
        tests/test_dns_parser.cpp
        tests/test_cpe_detector.cpp
        tests/test_rtt_tracker.cpp
        tests/test_loss_detector.cpp
    )

    add_executable(collector_tests ${TEST_SOURCES}
        # 复用被测代码（不含 main.cpp）
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
            UNIT_TEST_BUILD       # 测试专用宏，屏蔽DPDK硬件调用
    )

    target_link_libraries(collector_tests
        PRIVATE
            GTest::GTest
            GTest::Main
            -Wl,--whole-archive
            ${DPDK_WHOLE_ARCHIVE_LIBS}
            -Wl,--no-whole-archive
            ${DPDK_NORMAL_LIBS}
            ${PCAPPP_LIBRARIES}
            ${PCAP_LIBRARY}
            ${NDPI_LIBRARIES}
            Threads::Threads
            ${NUMA_LIBRARY}
            dl rt m
    )

    # 注册测试
    include(GoogleTest)
    gtest_discover_tests(collector_tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        TIMEOUT 30
    )

    message(STATUS "Unit tests enabled")
endif()

# ─────────────────────────────────────────────────────────
# 安装规则
# ─────────────────────────────────────────────────────────
install(TARGETS collector
    RUNTIME DESTINATION bin
)
install(DIRECTORY config/
    DESTINATION etc/collector
    FILES_MATCHING PATTERN "*.json"
)
install(DIRECTORY scripts/
    DESTINATION share/collector/scripts
    FILES_MATCHING PATTERN "*.sh"
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                GROUP_EXECUTE GROUP_READ
)

# ─────────────────────────────────────────────────────────
# 大页内存挂载辅助 target
# ─────────────────────────────────────────────────────────
if(ENABLE_HUGEPAGE)
    add_custom_target(setup_hugepages
        COMMAND ${CMAKE_SOURCE_DIR}/scripts/setup_hugepages.sh
        COMMENT "Setting up hugepages for DPDK"
        VERBATIM
    )
endif()

# ─────────────────────────────────────────────────────────
# 配置摘要
# ─────────────────────────────────────────────────────────
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
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "══════════════════════════════════════════")
message(STATUS "")