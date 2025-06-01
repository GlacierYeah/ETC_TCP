#!/usr/bin/env python3
# etc_client.py - ETC收费不停车系统客户端

import socket
import struct
import sys
import time
import os

# TCP标志位常量
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


# TCP报文头部结构
class TCPHeader:
    def __init__(self, src_port, dst_port, seq_num=0, ack_num=0,
                 data_offset=5, reserved=0, flags=0, window=1024,
                 checksum=0, urgent_ptr=0):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data_offset = data_offset  # 头部长度，单位是4字节
        self.reserved = reserved
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgent_ptr = urgent_ptr

    def pack(self):
        data_offset_reserved_flags = (self.data_offset << 12) + (self.reserved << 6) + self.flags
        header = struct.pack('!HHLLHHHH',
                             self.src_port,
                             self.dst_port,
                             self.seq_num,
                             self.ack_num,
                             data_offset_reserved_flags,
                             self.window,
                             self.checksum,
                             self.urgent_ptr)
        return header

    @staticmethod
    def unpack(packed_header):
        unpacked = struct.unpack('!HHLLHHHH', packed_header)
        src_port = unpacked[0]
        dst_port = unpacked[1]
        seq_num = unpacked[2]
        ack_num = unpacked[3]
        data_offset_reserved_flags = unpacked[4]
        data_offset = (data_offset_reserved_flags >> 12) & 0xF
        reserved = (data_offset_reserved_flags >> 6) & 0x3F
        flags = data_offset_reserved_flags & 0x3F
        window = unpacked[5]
        checksum = unpacked[6]
        urgent_ptr = unpacked[7]
        return TCPHeader(src_port, dst_port, seq_num, ack_num,
                         data_offset, reserved, flags, window,
                         checksum, urgent_ptr)

    def get_flags_description(self):
        """返回TCP标志位的描述信息"""
        flags_str = []
        if self.flags & FIN:
            flags_str.append("FIN")
        if self.flags & SYN:
            flags_str.append("SYN")
        if self.flags & RST:
            flags_str.append("RST")
        if self.flags & PSH:
            flags_str.append("PSH")
        if self.flags & ACK:
            flags_str.append("ACK")
        if self.flags & URG:
            flags_str.append("URG")
        return "|".join(flags_str) if flags_str else "无"

    def print_header_info(self, packet_type="未知"):
        """打印TCP头部详细信息"""
        print("=" * 60)
        print(f"TCP {packet_type}详细信息:")
        print("-" * 60)
        print(f"源端口: {self.src_port}")
        print(f"目标端口: {self.dst_port}")
        print(f"序列号: {self.seq_num}")
        print(f"确认号: {self.ack_num}")
        print(f"头部长度: {self.data_offset * 4} 字节")
        print(f"标志位: {self.flags:06b} ({self.get_flags_description()})")
        print(f"窗口大小: {self.window}")
        print(f"校验和: 0x{self.checksum:04x}")
        print(f"紧急指针: {self.urgent_ptr}")
        print("=" * 60)


# 计算校验和
def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xFFFF
    return checksum


# 显示数据包内容（简化或详细版）
def dump_packet_data(data, prefix="", detailed=False):
    if not detailed:
        try:
            # 提取TCP头后的数据作为消息
            if len(data) > 20:  # 至少有TCP头
                message = data[20:].decode('utf-8')
                print(f"{prefix}数据内容: \"{message}\"")
            else:
                print(f"{prefix}无有效数据")
        except UnicodeDecodeError:
            print(f"{prefix}无法解码的数据")
        return

    # 详细模式
    print(f"{prefix}数据包内容 ({len(data)} 字节):")
    print("-" * 60)

    # 显示头部和部分数据
    display_size = min(len(data), 40)
    hex_view = ""
    ascii_view = ""

    for i in range(display_size):
        if i % 16 == 0 and i > 0:
            print(f"{hex_view}  {ascii_view}")
            hex_view = ""
            ascii_view = ""

        hex_view += f"{data[i]:02x} "
        ascii_view += chr(data[i]) if 32 <= data[i] <= 126 else "."

    # 打印最后一行
    if hex_view:
        hex_view += "   " * (16 - (display_size % 16))
        print(f"{hex_view}  {ascii_view}")

    if len(data) > display_size:
        print(f"... (还有 {len(data) - display_size} 字节未显示)")
    print("-" * 60)


# 发送TCP数据包
def send_tcp_packet(sock, src_port, dst_port, seq_num, message, detailed=False):
    data = message.encode('utf-8')

    # 构造TCP头部
    header = TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        flags=PSH | ACK,  # PSH+ACK
        window=1024
    )

    # 计算校验和
    header_bytes = header.pack()
    header.checksum = calculate_checksum(header_bytes + data)
    header_bytes = header.pack()

    # 显示详细信息（如果需要）
    if detailed:
        header.print_header_info("发送数据包")

    # 发送数据包
    packet = header_bytes + data
    if detailed:
        dump_packet_data(packet, "发送", detailed)
    else:
        print(f"发送: \"{message}\"")

    sock.send(packet)
    return len(data)


# 接收TCP数据包
def recv_tcp_packet(sock, detailed=False):
    data = sock.recv(1024)
    if not data:
        return None, None

    # 如果数据包长度小于TCP头部长度，返回无效
    if len(data) < 20:
        print("接收到无效的数据包（长度小于20字节）")
        return None, None

    # 解析TCP头部
    header = TCPHeader.unpack(data[:20])
    payload = data[20:]

    # 显示详细信息（如果需要）
    if detailed:
        header.print_header_info("接收数据包")
        dump_packet_data(data, "接收", detailed)
    else:
        dump_packet_data(data, "接收", False)

    try:
        message = payload.decode('utf-8')
        return header, message
    except UnicodeDecodeError:
        print("接收到无法解码的数据")
        return header, None


# 清屏函数
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


# 显示菜单
def display_menu():
    print("\n" + "-" * 60)
    print("ETC收费不停车系统 - 车辆端")
    print("-" * 60)
    print("1. 身份验证与扣费")
    print("2. 紧急通讯")
    print("3. 显示TCP数据包详细信息")
    print("4. 退出系统")
    print("-" * 60)
    choice = input("请选择功能 (1-4): ")
    return choice


# 主函数
def main():
    clear_screen()
    print("\n***** ETC收费不停车系统 - 车辆端 *****\n")

    # 获取服务器连接信息
    server_ip = input("请输入服务器IP地址: ")
    server_port = int(input("请输入服务器端口号: "))

    print("\n正在连接到服务器...")

    # 创建TCP套接字并连接
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))
        print("连接成功!")
    except socket.error as e:
        print(f"连接失败: {e}")
        sys.exit(1)

    src_port = client_socket.getsockname()[1]  # 获取本地分配的端口
    seq_num = 0

    # 主循环
    while True:
        choice = display_menu()

        if choice == "1":  # 身份验证
            clear_screen()
            print("\n*** 身份验证与扣费 ***\n")

            # 发送身份验证请求
            send_tcp_packet(client_socket, src_port, server_port, seq_num, "1")
            seq_num += 1

            # 接收服务器确认
            header, response = recv_tcp_packet(client_socket)
            if not header or not response:
                continue

            # 输入车牌号
            plate = input("请输入车牌号: ")
            send_tcp_packet(client_socket, src_port, server_port, seq_num, plate)
            seq_num += len(plate)

            # 接收验证结果
            header, result = recv_tcp_packet(client_socket)
            if header and result:
                print("\n验证结果:", result)

            input("\n按Enter键返回主菜单...")
            clear_screen()

        elif choice == "2":  # 紧急通讯
            clear_screen()
            print("\n*** 紧急通讯 ***\n")

            # 发送通讯请求
            send_tcp_packet(client_socket, src_port, server_port, seq_num, "2")
            seq_num += 1

            # 接收服务器确认
            header, response = recv_tcp_packet(client_socket)
            if not header or not response:
                continue

            print("\n已建立通讯。输入'exit'结束通讯。")

            # 通讯循环
            while True:
                message = input("\n发送消息: ")
                send_tcp_packet(client_socket, src_port, server_port, seq_num, message)
                seq_num += len(message)

                if message.lower() == "exit":
                    # 接收服务器的通讯结束确认
                    header, end_msg = recv_tcp_packet(client_socket)
                    break

                # 接收服务器回复
                header, reply = recv_tcp_packet(client_socket)
                if not header or not reply:
                    break

            input("\n按Enter键返回主菜单...")
            clear_screen()



        elif choice == "3":  # 显示TCP数据包详细信息

            clear_screen()

            print("\n*** TCP数据包详细信息 ***\n")

            # 发送数据包详情请求

            send_tcp_packet(client_socket, src_port, server_port, seq_num, "3")

            seq_num += 1

            # 接收服务器确认

            header, response = recv_tcp_packet(client_socket)

            if not header or not response:
                continue

            print(f"服务器响应: {response}")

            # 让用户输入要发送的测试数据

            test_message = input("\n请输入要发送的测试数据: ")

            print("\n----发送数据包详细信息----")

            send_tcp_packet(client_socket, src_port, server_port, seq_num, test_message, detailed=True)

            seq_num += len(test_message)

            # 接收服务器的响应数据包

            print("\n----接收数据包详细信息----")

            header, server_response = recv_tcp_packet(client_socket, detailed=True)

            if header and server_response:
                print(f"\n服务器回复消息: {server_response}")

            input("\n按Enter键返回主菜单...")

            clear_screen()

        elif choice == "4":  # 退出系统
            print("\n正在关闭系统...")
            send_tcp_packet(client_socket, src_port, server_port, seq_num, "4")

            # 等待服务器确认
            try:
                header, response = recv_tcp_packet(client_socket)
                print("服务器回复:", response if response else "无响应")
            except:
                pass

            break

        else:
            print("无效的选择，请重新输入!")
            time.sleep(1)
            clear_screen()

    # 关闭连接
    client_socket.close()
    print("\n系统已关闭")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        sys.exit(0)