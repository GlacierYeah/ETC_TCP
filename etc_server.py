#!/usr/bin/env python3
# etc_server.py - ETC收费不停车系统服务器端

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


# 车辆信息类
class Vehicle:
    def __init__(self, plate, balance):
        self.plate = plate
        self.balance = balance


# 预定义车辆信息数组
vehicles = [
    Vehicle("ABC123", 50.0),
    Vehicle("XYZ789", 35.0),
    Vehicle("TEST001", 5.0)
]


# 主函数
def main():
    clear_screen()
    print("\n***** ETC收费不停车系统 - 服务器端 *****\n")

    # 设置监听参数
    port = int(input("请输入监听端口号: "))

    # 创建TCP套接字
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', port))
        server_socket.listen(1)
        print(f"\n服务器启动成功，正在监听端口 {port}...")
        print("-" * 60)
        print("等待车辆连接...\n")
    except socket.error as e:
        print(f"服务器启动失败: {e}")
        sys.exit(1)

    # 等待客户端连接
    client_socket, client_addr = server_socket.accept()
    print(f"车辆已连接: {client_addr[0]}:{client_addr[1]}")
    print("-" * 60)

    seq_num = 0
    src_port = server_socket.getsockname()[1]

    # 主处理循环
    while True:
        header, command = recv_tcp_packet(client_socket)
        if not header or not command:
            print("连接已断开")
            break

        # 根据命令进行处理
        if command == "1":  # 身份验证功能
            # 发送确认消息
            print("收到身份验证请求")
            send_tcp_packet(client_socket, src_port, header.src_port, seq_num, "请发送车牌号")
            seq_num += 12

            # 接收车牌号
            plate_header, plate = recv_tcp_packet(client_socket)
            if not plate_header or not plate:
                continue

            print(f"收到车牌号: {plate}")

            # 验证车牌号
            found = False
            response = ""
            for vehicle in vehicles:
                if vehicle.plate == plate:
                    found = True
                    if vehicle.balance >= 5.0:
                        vehicle.balance -= 5.0
                        response = f"身份验证成功，已扣费5元，余额{vehicle.balance:.2f}元"
                    else:
                        response = "余额不足，请走人工通道"
                    break

            if not found:
                response = "身份验证失败，请走人工通道"

            # 发送验证结果
            send_tcp_packet(client_socket, src_port, header.src_port, seq_num, response)
            seq_num += len(response)

        elif command == "2":  # 通讯功能
            print("收到通讯请求")
            send_tcp_packet(client_socket, src_port, header.src_port, seq_num, "已建立通讯连接")
            seq_num += 16

            while True:
                # 接收客户端消息
                msg_header, message = recv_tcp_packet(client_socket)
                if not msg_header or not message:
                    break

                if message.lower() == "exit":
                    send_tcp_packet(client_socket, src_port, header.src_port, seq_num, "通讯已结束")
                    seq_num += 12
                    break

                # 发送回复
                reply = input("请输入回复消息: ")
                send_tcp_packet(client_socket, src_port, header.src_port, seq_num, reply)
                seq_num += len(reply)



        elif command == "3":  # 详细显示TCP数据包

            print("收到数据包详情请求")

            send_tcp_packet(client_socket, src_port, header.src_port, seq_num, "请输入测试数据")

            seq_num += 12

            # 等待接收客户端测试数据包

            print("等待客户端发送测试数据包...")

            test_header, test_message = recv_tcp_packet(client_socket, detailed=True)

            if test_header and test_message:
                print(f"收到客户端测试数据: {test_message}")

                # 发送响应数据包

                response_message = f"服务器已收到您的测试数据: {test_message}"

                print("\n发送响应数据包...")

                send_tcp_packet(client_socket, src_port, test_header.src_port, seq_num, response_message, detailed=True)

                seq_num += len(response_message)

        elif command == "4":  # 退出系统
            print("收到退出请求，系统即将关闭")
            send_tcp_packet(client_socket, src_port, header.src_port, seq_num, "服务器已断开连接")
            break

        else:
            print(f"收到未知命令: {command}")
            send_tcp_packet(client_socket, src_port, header.src_port, seq_num, "未知命令")
            seq_num += 8

    # 关闭连接
    client_socket.close()
    server_socket.close()
    print("\n服务器已关闭")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        sys.exit(0)