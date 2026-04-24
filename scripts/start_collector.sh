#!/bin/bash
# MCX516A-CCAT 不需要绑定 vfio-pci，使用 bifurcated 模式
# 内核驱动 mlx5_core 保持加载

# 分配大页（100G线速需要更多）
echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
# 或使用1G大页（mlx5推荐，减少TLB miss）
echo 32 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages

# NUMA感知挂载
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# 启动参数说明：
# --allow: 使用PCI地址白名单（替代旧版-w）
# txq_inline_max=0: 纯收包场景关闭TX inline优化
# rx_vec_en=1: 启用向量化收包（吞吐提升30%+）
# mprq_en=1: 启用Multi-Packet RQ（单次DMA写多包，100G必备）
# mprq_log_stride_num=5: 每个MR包含32个stride
./collector \
    -l 0-31 \
    -n 4 \
    --huge-dir /mnt/huge \
    --file-prefix collector \
    --allow 0000:81:00.0,\
rx_vec_en=1,\
mprq_en=1,\
mprq_log_stride_num=5,\
mprq_log_stride_size=11,\
txq_inline_max=0,\
representor=0 \
    --allow 0000:81:00.1,rx_vec_en=1,mprq_en=1 \
    -- \
    -c config/collector.json