# UDPONICMP

## 通过ICMP承载UDP流量,主要用来解决UDP随机丢包问题

    1. 普通模式: 此模式需要设置: net.ipv4.icmp_echo_ignore_all=1
    2. EBPF模式: 需要使用Linux系统并且内核版本高于4.15,不需要禁用系统PING协议,推荐使用Ubuntu18.04

## 编译环境

    1. Golang 1.13+
    2. make,git 命令
    3. 如果使用EBPF模式

## 示例

    git clone https://github.com/czxichen/udponicmp.git
    cd udponicmp/example
    
    1. 不支持EBPF模式: make 
    2. 支持EBPF模式: make bpf