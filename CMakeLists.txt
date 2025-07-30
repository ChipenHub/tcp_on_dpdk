# 指定 CMake 最低版本要求
cmake_minimum_required(VERSION 3.10)

# 定义项目名称和语言
project(tstack C)

# 查找 pkg-config（因为我们需要用它来获取 DPDK 的信息）
find_package(PkgConfig REQUIRED)

# 使用 pkg-config 查找 libdpdk
pkg_check_modules(DPDK REQUIRED libdpdk)

# 添加可执行文件
add_executable(ustack tstack.c arp.h)

# 链接 DPDK 库并设置编译选项
target_include_directories(ustack PRIVATE ${DPDK_INCLUDE_DIRS})
target_link_libraries(ustack PRIVATE ${DPDK_LIBRARIES})
target_compile_options(ustack PRIVATE ${DPDK_CFLAGS})
