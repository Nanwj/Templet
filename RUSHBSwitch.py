import math

from datetime import datetime

from scapy.all import raw, struct
from scapy.fields import BitField, StrLenField
from scapy.packet import Packet

import socket
import sys
import traceback
import os.path
import time
import threading
import ipaddress


RUSHB_PROTOCOL_VERSION = "0.4"
"""
0.1 - Initial release
0.2 - Add *out file and fix bugs
0.3 - Add sleep for sending message
0.4 - Add new tests
0.5 - Fix new tests
"""

LOCAL_HOST = "127.0.0.1"
RECV_SIZE = 4096
TIME_OUT = 5

DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACKNOWLEDGE = 0x04
DATA = 0x05
QUERY = 0x06
AVAILABLE = 0x07
LOCATION = 0x08
DISTANCE = 0x09
MORE_FRAG = 0x0a
END_FRAG = 0x0b
INVALID = 0x00


# 包 包含源地址，目的地址，offset以及mode
class RUSH(Packet):
    name = "RUSH"
    fields_desc = [
        BitField("source_ip", 0, 32),
        BitField("destination_ip", 0, 32),
        BitField("offset", 0, 24),
        BitField("mode", 0, 8),
    ]

# IP类 包含IP
class RUSHIp(RUSH):
    name = "RUSH_IP"
    fields_desc = [
        BitField("ip", 0, 32),
    ]

# 数据类 包含data
class RUSHData(RUSH):
    name = "RUSH_DATA"
    fields_desc = [
        StrLenField("data", "", length_from=lambda x: x.length),
    ]

# 地址类，包含 x 和 y
class RUSHLocation(RUSH):
    name = "RUSH_LOCATION"
    fields_desc = [
        BitField("x", 0, 16),
        BitField("y", 0, 16),
    ]

# 距离类，包含 目标IP和距离
class RUSHDistance(RUSH):
    name = "RUSH_DISTANCE"
    fields_desc = [
        BitField("target_ip", 0, 32),
        BitField("distance", 0, 32),
    ]


def longest_prefix_matching(compared_ip, ip_list):
    bin_compared_ip = bin(ip_to_int(compared_ip))
    result = (None, 0)
    calculate = 0

    for ip in ip_list:
        bin_ip = bin(ip_to_int(ip))

        for index, b in enumerate(bin_compared_ip):
            if b == bin_ip[index]:
                calculate += 1
            else:
                break
            
        if calculate > result[1]:
            result = (ip, calculate)
        
        calculate = 0

    return result[0]


def int_to_bytes(integer,size):
    return integer.to_bytes(size, byteorder='big')

def str_to_int(string):
    b_str = string.encode("UTF-8")
    return int.from_bytes(b_str, byteorder='big')


def int_to_str(integer, size=11):
    return integer.to_bytes(size, byteorder='big').decode("UTF-8")


def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def calculate_distance(point1, point2):
    x1 = point1.getfieldval("x")
    y1 = point1.getfieldval("y")
    x2 = point2.getfieldval("x")
    y2 = point2.getfieldval("y")

    result = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)

    return math.floor(result)

    

# 创建一个packet
def build_packet(source_ip, destination_ip, offset, mode, misc=None):
    # 源地址
    s_ip = ip_to_int(source_ip)         
    # 目的地址
    d_ip = ip_to_int(destination_ip)    
    try:
        pkt = RUSH(source_ip=s_ip, destination_ip=d_ip, offset=offset, mode=mode)
        if mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            t_ip = ip_to_int(misc)
            additional = RUSHIp(ip=t_ip)
        elif mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
            additional = misc.encode('utf-8')
        elif mode == LOCATION:
            additional = RUSHLocation(x=misc[0], y=misc[1])
        elif mode is DISTANCE:
            t_ip = ip_to_int(misc[0])
            additional = RUSHDistance(target_ip=t_ip, distance=misc[1])
        else:
            additional = None
    except:
        traceback.print_exc(file=sys.stderr)
        assert False, f"There is a problem while building packet."
    return pkt, additional


def int_to_location(data):
    x = data & 0x11110000 >> 8
    y = data & 0x00001111
    return f'x = {x}, y = {y}'


def new_tcp_socket(port) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LOCAL_HOST, port))
    return sock

def bytes_to_int(data):
    return int.from_bytes(data, byteorder='big')


def new_udp_socket(port) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL_HOST, port))
    return sock


def get_info_file(file_path, skip=0):
    info = None
    try:
        while not os.path.exists(file_path):
            time.sleep(1)
        if os.path.isfile(file_path):
            time.sleep(3)
            f = open(file_path, "r")
            for i in range(skip):
                f.readline()
            target_port = int(f.readline())
            info = (LOCAL_HOST, target_port)
    except:
        traceback.print_exc(file=sys.stderr)
        assert False, f"Error while getting the file."
    return info



class PureLocalSwitch():
    def __init__(self, type, server, x, y):
        self.type = type                                                        # local or global
        self._IP = server.split('/', 1)[0]                                      # IP地址
        self._sub_net = server.split('/', 1)[1]                                 # 子网掩码
        self._location_x = int(x)                                               # x 坐标
        self._location_y = int(y)                                               # y 坐标

        self._UDP_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     # UDP套接字
        self._UDP_socket.bind((LOCAL_HOST, 0))
        
        self._assigned_IP = ''                                                  # 记录分配给请求连接的Switch IP
        self._distributed_IP = ''                                               # 记录被分配IP
        self._destination_IP = ''                                               # 记录分配给本Switch的Switch的 IP
        self._adapter_IP = dict()
        self._outdegree_IP = dict()

        self._outdegree_socket = list()                                         # 记录所有成功连接到其他Switch的套接字
        self._RIP_Table = dict()                                                # RIP 表记录最短路径

        self.lock = threading.Lock()

        self.time = None
        self._DATA = []
        self._start_position = None

    def __repr__(self) -> str:
        print(self.type + " Switch :")

    def __str__(self) -> str:
        return ("Switch(" + self.type + " IP: " + str(self._IP) + "/" + str(self._sub_net) + " (" 
        + str(self._location_x) + ", " + str(self._location_y) + "))")


    # 分配连接到本Switch的IP并返回
    def distribute_IP(self, IP):
        if len(self._adapter_IP) == 0:
            result = ip_to_int(IP) + 1
        else:
            inverse = [(value, key) for key, value in self._adapter_IP.items()]
            result = ip_to_int(max(inverse)[1]) + 1

        return int_to_ip(result)


    # 将packet， 附加信息， 目标IP， 是否打印以及打印信息传入发送并打印
    def send_UDP_packet(self, packet, additional, target_IP=None, print_out=False, extend_message=""):
        message = raw(packet)
        if additional is not None:
            message += raw(additional)
        if target_IP is None:
            self._UDP_socket.sendall(message)
        else:
            self._UDP_socket.sendto(message, target_IP)
        
        if print_out:
            print("should print out someting")


    # 将packet， 附加信息， 目标IP， 是否打印以及打印信息传入发送并打印
    def send_TCP_packet(self, packet, additional, socket, print_out=False, extend_message=""):
        message = raw(packet)
        if additional is not None:
            message += raw(additional)
        # if target_IP is None:
        #     self._UDP_socket.sendall(message)
        # else:

        socket.send(message)
        
        if print_out:
            print("should print out someting")


    # 用于监听UDP协议实现Greeting并分配IP
    def receive(self, print_out=False, extend_message=""):
        raw_data, router = self._UDP_socket.recvfrom(RECV_SIZE)
        mode = raw_data[11]
        packet = RUSH(raw_data[:12])
        left_info = raw_data[12:]

        # 收到DISCOVER包后
        if mode == DISCOVERY:
            self._assigned_IP = self.distribute_IP(self._IP)
            packet, additional = build_packet(self._IP, "0.0.0.0", 0x000000, OFFER, self._assigned_IP)
            self.send_UDP_packet(packet, additional, router)
            
        # 收到REQUEST包后
        if mode == REQUEST:
            packet, additional = build_packet(self._IP, self._assigned_IP, 0x000000, ACKNOWLEDGE, self._assigned_IP)
            self.send_UDP_packet(packet, additional, router)
            self._adapter_IP[self._assigned_IP]= router[1]
            self._RIP_Table[self._assigned_IP] = [0, self._IP, self._assigned_IP, self._UDP_socket, "Adapter"]
            self._assigned_IP = ""

        
        # UDP 接收端
        # 收到DATA包
        if mode == DATA:
            message = left_info.decode('utf-8')
            self.time = datetime.now()

            # 切割data包
            if len(message) > 1488:
                while len(message) > 1488:
                    self._DATA.append(message[:1488])
                    message = message[1488:]
            else:
                self._DATA.append(message)
                self._start_position = 0

            aim_ip = int_to_ip(bytes_to_int(raw_data[4:8]))
            source_ip = int_to_ip(bytes_to_int(raw_data[:4]))

            # 如果包的目标地址是自己
            if aim_ip == self._IP:
                sys.stdout.write('Received from ' + source_ip + ': ' + left_info.decode('utf-8') + '\n')
                sys.stdout.flush()
                
            
            # 如果包的目的地址是Aapter
            elif aim_ip in self._adapter_IP.keys():
                pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                self.send_UDP_packet(pkt, additional, ("127.0.0.1", self._adapter_IP[aim_ip]))            
            
            # 如果包的目的地址存储在RIP Table中
            elif aim_ip in self._RIP_Table.keys():
                pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
            else:
                target = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                pkt, additional = build_packet(source_ip, target, 0x000000, QUERY)
                self.send_TCP_packet(pkt, additional, self._RIP_Table[target][3])


        # UDP接收端
        # 收到AVAILABLE包
        if mode == AVAILABLE:
            if (datetime.now() - self.time).seconds < 5:
                self.lock.acquire()

                aim_ip = int_to_ip(bytes_to_int(raw_data[:4]))
                for message in self._DATA:
                    pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), self._start_position, DATA, self._DATA[0])
                    # 判断应该发送给Adapter还是Switch
                    if aim_ip in self._adapter_IP.keys():
                        self.send_UDP_packet(pkt, additional, ("127.0.0.1", self._adapter_IP[aim_ip]))
                    elif aim_ip in self._RIP_Table.keys():
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                    else:
                        ip = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[ip][3])

                    if len(self._DATA) > 1:
                        self._start_position = len(self._DATA[0])
                    else:
                        self._start_position = None
                    self._DATA.pop(0)

                self.lock.release()

    
    # Greeting - UDP
    def UDP_greeting(self):
        while True:
            self.receive()


    # 检查input输入并建立相应TCP连接
    def commandline_interface(self):
        port_num = str(self._UDP_socket.getsockname()[1])
        # sys.stdout.write(port_num + "\n" + "> ")
        # sys.stdout.flush()
        print(port_num)
        while True:

            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError as e:
                print("有错误")
                return
            else:
                self.handling_input(user_input)


    # 对用户的input进行操作
    def handling_input(self, user_input):
        user_input_split = user_input.split(maxsplit=2) # prevent splitting data
        (connect, send) = (False, False)
        if len(user_input_split) == 2:
            command = user_input_split[0]
            destination = user_input_split[1]
            connect = True
        elif len(user_input_split) == 3:
            command = user_input_split[0]
            destination = user_input_split[1]
            data = user_input_split[2]
            send = True
        else:
            return
        # Create packet and send

        if connect and command == "connect":
            time.sleep(0.3)     # 我也不知道为啥要设置0.3秒延迟

            # 开启一个线程来建立TCP连接
            TCP_connection = threading.Thread(target=self.TCP_connection, args=(int(destination),))
            TCP_connection.start()



    # TCP 发送端
    # TCP 连接监听并发包
    def TCP_connection(self, destination_port):
        TCP_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCP_socket.connect((LOCAL_HOST, destination_port))
        # 创建DISCOVERY包
        packet, additional = build_packet("0.0.0.0", "0.0.0.0", 0x000000, DISCOVERY, "0.0.0.0")
        self.send_TCP_packet(packet, additional, TCP_socket)

        while True:
            try:
                raw_data = TCP_socket.recv(1024)
                mode = raw_data[11]
                packet = RUSH(raw_data[:12])
                left_info = raw_data[12:]

                # 收到OFFER之后:
                if mode == OFFER:
                    self._destination_IP = str(ipaddress.IPv4Address(raw_data[:4]))
                    self._distributed_IP = str(ipaddress.IPv4Address(int.from_bytes(raw_data[12:16], byteorder='big')))
                    packet, additional = build_packet("0.0.0.0", self._destination_IP, 0x000000, REQUEST, self._distributed_IP)
                    self.send_TCP_packet(packet, additional, TCP_socket)

                # 收到ACKNOWLEDGE包后
                if mode == ACKNOWLEDGE:
                    packet, additional = build_packet(self._distributed_IP, self._destination_IP, 0x000000, LOCATION, (self._location_x, self._location_y))
                    self.send_TCP_packet(packet, additional, TCP_socket)
                

                # TCP 发送端:
                # 收到LOCATION包后
                if mode == LOCATION:
                    distance = calculate_distance(RUSHLocation(x=self._location_x, y=self._location_y), RUSHLocation(raw_data[12:]))

                    if self._RIP_Table:
                        self.lock.acquire()

                        # 发送端开始发送广播
                        for key, val in self._RIP_Table.items():
                            # 向邻居广播新的DISTANCE包
                            if (key == val[2] and key != self._destination_IP):
                                pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (self._destination_IP, (distance + val[0])))
                                self.send_TCP_packet(pkt, additional, val[3])

                        self.lock.release()

                        self._RIP_Table[int_to_ip(packet.getfieldval("source_ip"))] = [distance, self._distributed_IP, self._destination_IP, TCP_socket, "Switch"]

                    else:
                        self._RIP_Table[int_to_ip(packet.getfieldval("source_ip"))] = [distance, self._distributed_IP, self._destination_IP, TCP_socket, "Switch"]


                    self._outdegree_IP[self._destination_IP] = destination_port
                    self._outdegree_socket.append(TCP_socket)
                    self._distributed_IP = ""
                    self._destination_IP = ""


                # 收到DISTANCE包
                if mode == DISTANCE:

                    target_ip = int_to_ip(bytes_to_int(raw_data[12:16]))
                    distance = bytes_to_int(raw_data[16:])
                    if distance <= 1000:
                        if target_ip in self._RIP_Table.keys():
                            if self._RIP_Table[target_ip][0] > distance:
                                self._RIP_Table[target_ip] = [distance, int_to_ip(packet.getfieldval("destination_ip")), int_to_ip(packet.getfieldval("source_ip")), socket, "Switch"]

                                # 广播更新最短路径
                                ip_checklist = [int_to_ip(packet.getfieldval("source_ip")), int_to_ip(packet.getfieldval("destination_ip")), target_ip]
                                
                                self.lock.acquire()
                                for key, val in self._RIP_Table.items():
                                    # 向邻居广播新的DISTANCE包
                                    if ((key == val[2]) and (key not in ip_checklist) ):
                                        pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (target_ip, (distance + val[0])))
                                        self.send_TCP_packet(pkt, additional, val[3])
                                self.lock.release()
                        else:
                            self._RIP_Table[target_ip] = [distance, int_to_ip(packet.getfieldval("destination_ip")), int_to_ip(packet.getfieldval("source_ip")), socket, "Switch"]

                            ip_checklist = [int_to_ip(packet.getfieldval("source_ip")), int_to_ip(packet.getfieldval("destination_ip")), target_ip]

                            self.lock.acquire()
                            # 广播更新最短路径
                            for key, val in self._RIP_Table.items():
                                # 向邻居广播新的DISTANCE包
                                if ((key == val[2]) and (key not in ip_checklist) ):
                                    pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (target_ip, (distance + val[0])))
                                    self.send_TCP_packet(pkt, additional, val[3])
                            self.lock.release()

                
                # 收到QUERY包
                if mode == QUERY:
                    pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), 0x000000, AVAILABLE)
                    self.send_TCP_packet(pkt, additional, TCP_socket)


                # 收到AVAILABLE包
                if mode == AVAILABLE:
                    if (datetime.now() - self.time).seconds < 5:
                        self.lock.acquire()

                        aim_ip = int_to_ip(bytes_to_int(raw_data[:4]))
                        for message in self._DATA:
                            source = int_to_ip(bytes_to_int(raw_data[4:8]))
                            dest = int_to_ip(bytes_to_int(raw_data[:4]))
                            pkt, additional = build_packet(source, dest, self._start_position, DATA, self._DATA[0])
                            # 判断应该发送给Adapter还是Switch

                            if aim_ip in self._adapter_IP.keys():
                                self.send_UDP_packet(pkt, additional, ("127.0.0.1", self._adapter_IP[aim_ip]))
                            elif aim_ip in self._RIP_Table.keys():
                                self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                            else:
                                ip = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                                self.send_TCP_packet(pkt, additional, self._RIP_Table[ip][3])

                            if len(self._DATA) > 1:
                                self._start_position = len(self._DATA[0])
                            else:
                                self._start_position = None
                            self._DATA.pop(0)

                        self.lock.release()


                # 收到DATA包
                if mode == DATA:
                    message = left_info.decode('utf-8')
                    self.time = datetime.now()
                    # 切割data包
                    if len(message) > 1488:
                        while len(message) > 1488:
                            self._DATA.append(message[:1488])
                            message = message[1488:]
                    else:
                        self._DATA.append(message)
                        self._start_position = 0

                    aim_ip = int_to_ip(bytes_to_int(raw_data[4:8]))
                    source_ip = int_to_ip(bytes_to_int(raw_data[:4]))

                    # 如果包的目标地址是自己
                    if aim_ip == self._IP:
                        sys.stdout.write('Received from ' + source_ip + ': ' + left_info.decode('utf-8') + '\n')
                        sys.stdout.flush()
                    
                    # 如果包的目的地址是Aapter
                    elif aim_ip in self._adapter_IP.keys():
                        pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                        self.send_UDP_packet(pkt, additional, self._adapter_IP[aim_ip])


                    # 如果包的目的地址存储在RIP Table中
                    elif aim_ip in self._RIP_Table.keys():
                        pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                    else:
                        target = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                        pkt, additional = build_packet(source_ip, target, 0x000000, QUERY)
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[target][3])

            except:
                break

class LocalGlobalSwitch():
    def __init__(self, type, server_UDP, server_TCP, x, y):
        self.type = type + "/global"                                                    # local and global
        self._UDP_IP = server_UDP.split('/', 1)[0]                                      # UDP IP地址
        self._UDP_sub_net = server_UDP.split('/', 1)[1]                                 # UDP 子网掩码
        self._TCP_IP = server_TCP.split('/', 1)[0]                                      # UDP IP地址
        self._TCP_sub_net = server_TCP.split('/', 1)[1]                                 # UDP 子网掩码
        self._location_x = int(x)                                                       # x 坐标
        self._location_y = int(y)                                                       # y 坐标

        self._UDP_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)             # UDP 接收套接字
        self._UDP_socket.bind((LOCAL_HOST, 0))  

        self._TCP_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)            # TCP 发送套接字
        self._TCP_socket.bind((LOCAL_HOST, 0))
        self._TCP_socket.listen(5)
                
        self._UDP_assigned_IP = ""
        self._TCP_assigned_IP = ""
        self._adapter_IP = dict()
        self._switch_IP = dict()

        self._indegree_socket = list()                                                  # 记录所有成功连接到本Switch的套接字
        self._RIP_Table = dict()                                                        # RIP 表记录最短路径

        self.lock = threading.Lock()

        self.time = None
        self._DATA = []
        self._start_position = None


        print(str(self._UDP_socket.getsockname()[1]) + "\n" + str(self._TCP_socket.getsockname()[1]) + "\n" + "> ", end="", flush=True)


    # 分配连接到本Switch的 UDP IP并返回
    def distribute_UDP_IP(self, IP):
        if len(self._adapter_IP) == 0:
            result = ip_to_int(IP) + 1
        else:
            inverse = [(value, key) for key, value in self._adapter_IP.items()]
            result = ip_to_int(max(inverse)[1]) + 1

        return int_to_ip(result)

    # 分配连接到本Switch的 TCP IP并返回
    def distribute_TCP_IP(self, IP):
        if len(self._switch_IP) == 0:
            result = ip_to_int(IP) + 1
        else:
            inverse = [(value, key) for key, value in self._switch_IP.items()]
            result = ip_to_int(max(inverse)[1]) + 1

        return int_to_ip(result)

    
    # 发送UDP包
    # 将packet， 附加信息， 目标IP， 是否打印以及打印信息传入发送并打印
    def send_UDP_packet(self, packet, additional, target_IP=None, print_out=False, extend_message=""):
        message = raw(packet)
        if additional is not None:
            message += raw(additional)
        if target_IP is None:
            self._UDP_socket.sendall(message)
        else:
            self._UDP_socket.sendto(message, target_IP)
        
        if print_out:
            print("should print out someting")


    # 发送TCP包
    # 将packet， 附加信息， 目标IP， 是否打印以及打印信息传入发送并打印
    def send_TCP_packet(self, packet, additional, socket, print_out=False, extend_message=""):
        message = raw(packet)
        if additional is not None:
            message += raw(additional)

        socket.send(message)
        
        if print_out:
            print("should print out someting")
            

    # UDP 接收端
    # 用于监听UDP协议实现Greeting并分配IP
    def UDP_receive(self, print_out=False, extend_message=""):
        raw_data, router = self._UDP_socket.recvfrom(RECV_SIZE)
        mode = raw_data[11]
        packet = RUSH(raw_data[:12])
        left_info = raw_data[12:]

        # 收到DISCOVER包后
        if mode == DISCOVERY:
            self._UDP_assigned_IP = self.distribute_UDP_IP(self._UDP_IP)
            packet, additional = build_packet(self._UDP_IP, "0.0.0.0", 0x000000, OFFER, self._UDP_assigned_IP)
            self.send_UDP_packet(packet, additional, router)
            
        # 收到REQUEST包后
        if mode == REQUEST:
            packet, additional = build_packet(self._UDP_IP, self._UDP_assigned_IP, 0x000000, ACKNOWLEDGE, self._UDP_assigned_IP)
            self.send_UDP_packet(packet, additional, router)
            self._adapter_IP[self._UDP_assigned_IP]= router[1]
            self._RIP_Table[self._UDP_assigned_IP] = [0, self._UDP_IP, self._UDP_assigned_IP, self._UDP_socket, "Adapter"]
            self._UDP_assigned_IP = ""


        # UDP 接收端
        # 收到DATA包
        if mode == DATA:
            message = left_info.decode('utf-8')
            self.time = datetime.now()

            # 切割data包
            if len(message) > 1488:
                while len(message) > 1488:
                    self._DATA.append(message[:1488])
                    message = message[1488:]
            else:
                self._DATA.append(message)
                self._start_position = 0

            aim_ip = int_to_ip(bytes_to_int(raw_data[4:8]))
            source_ip = int_to_ip(bytes_to_int(raw_data[:4]))

            # 如果包的目标地址是自己
            if aim_ip == self._UDP_IP:
                sys.stdout.write('Received from ' + source_ip + ': ' + left_info.decode('utf-8') + '\n')
                sys.stdout.flush()
                
            
            # 如果包的目的地址是Aapter
            elif aim_ip in self._adapter_IP.keys():
                pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                self.send_UDP_packet(pkt, additional, ("127.0.0.1", self._adapter_IP[aim_ip]))
            
            # 如果包的目的地址存储在RIP Table中
            elif aim_ip in self._RIP_Table.keys():
                pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
            else:
                target = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                pkt, additional = build_packet(source_ip, target, 0x000000, QUERY)
                self.send_TCP_packet(pkt, additional, self._RIP_Table[target][3])


        # UDP接收端
        # 收到AVAILABLE包
        if mode == AVAILABLE:
            if (datetime.now() - self.time).seconds < 5:
                self.lock.acquire()

                aim_ip = int_to_ip(bytes_to_int(raw_data[:4]))
                for message in self._DATA:
                    pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), self._start_position, DATA, self._DATA[0])
                    # 判断应该发送给Adapter还是Switch
                    if aim_ip in self._adapter_IP.keys():
                        self.send_UDP_packet(pkt, additional, ("127.0.0.1", self._adapter_IP[aim_ip]))
                    elif aim_ip in self._RIP_Table.keys():
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                    else:
                        ip = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[ip][3])

                    if len(self._DATA) > 1:
                        self._start_position = len(self._DATA[0])
                    else:
                        self._start_position = None
                    self._DATA.pop(0)

                self.lock.release()

    
    # UDP 接收端
    # Greeting - UDP
    def UDP_greeting(self):
        while True:
            self.UDP_receive()


    
    # TCP 接收端
    # 用于监听TCP协议实现Greeting并分配IP
    def TCP_receive(self, print_out=False, extend_message=""):
        connect, address = self._TCP_socket.accept()
        if connect:            
            # 开启一个线程来监听该用户与本Switch的TCP协议
            thread = threading.Thread(target=self.TCP_intereface, args=(connect, address, connect, ))
            thread.start()

        
    # TCP 接收端
    # 当一个socket向本Switch开启了一个TCP连接后:
    def TCP_intereface(self, socket, address, connect):
        while True:
            try:
                raw_data = socket.recv(1024)
                mode = raw_data[11]
                packet = RUSH(raw_data[:12])
                left_info = raw_data[12:]

                # 收到DISCOVER包后
                if mode == DISCOVERY:
                    self._TCP_assigned_IP = self.distribute_TCP_IP(self._TCP_IP)
                    packet, additional = build_packet(self._TCP_IP, "0.0.0.0", 0x000000, OFFER, self._TCP_assigned_IP)
                    self.send_TCP_packet(packet, additional, socket)
                    
                # 收到REQUEST包后
                if mode == REQUEST:
                    packet, additional = build_packet(self._TCP_IP, self._TCP_assigned_IP, 0x000000, ACKNOWLEDGE, self._TCP_assigned_IP)
                    self.send_TCP_packet(packet, additional, socket)

                # TCP 接收端:
                # 收到LOCATION包之后
                if mode == LOCATION:
                    packet, additional = build_packet(self._TCP_IP, self._TCP_assigned_IP, 0x000000, LOCATION, (self._location_x, self._location_y))
                    self.send_TCP_packet(packet, additional, socket)

                    distance = calculate_distance(RUSHLocation(x=self._location_x, y=self._location_y), RUSHLocation(raw_data[12:]))

                    # 广播自己的UDP端口
                    pkt, additional = build_packet(self._TCP_IP, self._TCP_assigned_IP, 0x000000, DISTANCE, (self._UDP_IP, (distance)))
                    self.send_TCP_packet(pkt, additional, socket)
                    self._RIP_Table[self._TCP_assigned_IP] = [distance, self._IP, self._TCP_assigned_IP, socket, "Switch"]


                    self._switch_IP[self._TCP_assigned_IP]= address[1]
                    self._TCP_assigned_IP = ""
                    
                    self._indegree_socket.append(connect)


                # 收到DISTANCE包
                if mode == DISTANCE:

                    target_ip = int_to_ip(bytes_to_int(raw_data[12:16]))
                    distance = bytes_to_int(raw_data[16:])
                    if distance <= 1000:
                        if target_ip in self._RIP_Table.keys():
                            if self._RIP_Table[target_ip][0] > distance:
                                self._RIP_Table[target_ip] = [distance, int_to_ip(packet.getfieldval("destination_ip")), int_to_ip(packet.getfieldval("source_ip")), socket, "Switch"]

                                # 广播更新最短路径
                                ip_checklist = [int_to_ip(packet.getfieldval("source_ip")), int_to_ip(packet.getfieldval("destination_ip")), target_ip]
                                self.lock.acquire()
                                for key, val in self._RIP_Table.items():
                                    # 向邻居广播新的DISTANCE包
                                    if ((key == val[2]) and (key not in ip_checklist) ):
                                        pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (target_ip, (distance + val[0])))
                                        self.send_TCP_packet(pkt, additional, val[3])
                                self.lock.release()
                        else:
                            self._RIP_Table[target_ip] = [distance, int_to_ip(packet.getfieldval("destination_ip")), int_to_ip(packet.getfieldval("source_ip")), socket, "Switch"]

                            ip_checklist = [int_to_ip(packet.getfieldval("source_ip")), int_to_ip(packet.getfieldval("destination_ip")), target_ip]
                            
                            # 广播更新最短路径
                            self.lock.acquire()
                            for key, val in self._RIP_Table.items():
                                # 向邻居广播新的DISTANCE包
                                if ((key == val[2]) and (key not in ip_checklist) ):
                                    pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (target_ip, (distance + val[0])))
                                    self.send_TCP_packet(pkt, additional, val[3])
                            self.lock.release()
                            

                # 收到QUERY包
                if mode == QUERY:
                    pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), 0x000000, AVAILABLE)
                    self.send_TCP_packet(pkt, additional, socket)


                # 收到AVAILABLE包
                if mode == AVAILABLE:
                    if (datetime.now() - self.time).seconds < 5:
                        self.lock.acquire()

                        aim_ip = int_to_ip(bytes_to_int(raw_data[:4]))
                        for message in self._DATA:
                            pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), self._start_position, DATA, self._DATA[0])
                            # 判断应该发送给Adapter还是Switch
                            if aim_ip in self._adapter_IP.keys():
                                self.send_UDP_packet(pkt, additional, ("127.0.0.1", self._adapter_IP[aim_ip]))
                            elif aim_ip in self._RIP_Table.keys():
                                self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                            else:
                                ip = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                                self.send_TCP_packet(pkt, additional, self._RIP_Table[ip][3])
                            if len(self._DATA) > 1:
                                self._start_position = len(self._DATA[0])
                            else:
                                self._start_position = None
                            self._DATA.pop(0)

                        self.lock.release()


                # 收到DATA包
                if mode == DATA:
                    message = left_info.decode('utf-8')
                    self.time = datetime.now()
                    # 切割data包
                    if len(message) > 1488:
                        while len(message) > 1488:
                            self._DATA.append(message[:1488])
                            message = message[1488:]
                    else:
                        self._DATA.append(message)
                        self._start_position = 0

                    aim_ip = int_to_ip(bytes_to_int(raw_data[4:8]))
                    source_ip = int_to_ip(bytes_to_int(raw_data[:4]))

                    # 如果包的目标地址是自己
                    if aim_ip == self._IP:
                        sys.stdout.write('Received from ' + source_ip + ': ' + left_info.decode('utf-8') + '\n')
                        sys.stdout.flush()
                    
                    # 如果包的目的地址是Aapter
                    elif aim_ip in self._adapter_IP.keys():
                        pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                        self.send_UDP_packet(pkt, additional, self._adapter_IP[aim_ip])

                    # 如果包的目的地址存储在RIP Table中
                    elif aim_ip in self._RIP_Table.keys():
                        pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                    else:
                        target = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                        pkt, additional = build_packet(source_ip, target, 0x000000, QUERY)
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[target][3])

            except:
                break


    # TCP 接收端
    # Greeting - TCP
    def TCP_greeting(self):
        while True:
            self.TCP_receive()


class PureGlobalSwitch():
    def __init__(self, type, server, x, y):
        self.type = type                                                            # local or global
        self._IP = server.split('/', 1)[0]                                          # IP地址
        self._sub_net = server.split('/', 1)[1]                                     # 子网掩码
        self._location_x = int(x)                                                   # x 坐标
        self._location_y = int(y)                                                   # y 坐标


        self._TCP_socket_reseve = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP 接收套接字
        self._TCP_socket_reseve.bind((LOCAL_HOST, 0))
        self._TCP_socket_reseve.listen(5)


        self._assigned_IP = '' 
        self._distributed_IP = '' 
        self._destination_IP = '' 
        self._indegree_IP = dict()
        self._outdegree_IP = dict()

        self._indegree_socket = list()                                              # 记录所有成功连接到本Switch的套接字
        self._outdegree_socket = list()                                             # 记录所有成功连接到其他Switch的套接字
        self._all_sockets = list()                                                  # 记录所有成功连接的套接字
        self._RIP_Table = dict()                                                    # RIP 表记录最短路径

        self.lock = threading.Lock()

        self.time = None
        self._DATA = []
        self._start_position = None


    def __repr__(self) -> str:
        print(self.type + " Switch :")

    def __str__(self) -> str:
        return ("Switch(" + self.type + " IP: " + str(self._IP) + "/" + str(self._sub_net) + " (" 
        + str(self._location_x) + ", " + str(self._location_y) + "))")


    # 分配连接到本Switch的IP并返回
    def distribute_IP(self, IP):
        if len(self._indegree_IP) == 0:
            result = ip_to_int(IP) + 1
        else:
            inverse = [(value, key) for key, value in self._indegree_IP.items()]
            result = ip_to_int(max(inverse)[1]) + 1

        return int_to_ip(result)

    
    # 将packet， 附加信息， 目标IP， 是否打印以及打印信息传入发送并打印
    def send_TCP_packet(self, packet, additional, socket, print_out=False, extend_message=""):
        message = raw(packet)
        if additional is not None:
            message += raw(additional)
        # if target_IP is None:
        #     self._UDP_socket.sendall(message)
        # else:

        socket.send(message)
        
        if print_out:
            print("should print out someting")


    # TCP 接收端
    # 用于监听TCP协议实现Greeting并分配IP
    def receive(self, print_out=False, extend_message=""):
        connect, address = self._TCP_socket_reseve.accept()
        if connect:
            # 开启一个线程来监听该用户与本Switch的TCP协议
            thread = threading.Thread(target=self.TCP_intereface, args=(connect, address, connect, ))
            thread.start()

        
    # TCP 接收端
    # 当一个socket向本Switch开启了一个TCP连接后:
    def TCP_intereface(self, socket, address, connect):
        while True:
            try:
                raw_data = socket.recv(1024)
                mode = raw_data[11]
                packet = RUSH(raw_data[:12])
                left_info = raw_data[12:]

                # 收到DISCOVER包后
                if mode == DISCOVERY:
                    self._assigned_IP = self.distribute_IP(self._IP)
                    packet, additional = build_packet(self._IP, "0.0.0.0", 0x000000, OFFER, self._assigned_IP)
                    self.send_TCP_packet(packet, additional, socket)
                    
                # 收到REQUEST包后
                if mode == REQUEST:
                    packet, additional = build_packet(self._IP, self._assigned_IP, 0x000000, ACKNOWLEDGE, self._assigned_IP)
                    self.send_TCP_packet(packet, additional, socket)
                    


                # TCP 接收端:
                # 收到LOCATION包之后
                if mode == LOCATION:
                    packet, additional = build_packet(self._IP, self._assigned_IP, 0x000000, LOCATION, (self._location_x, self._location_y))
                    self.send_TCP_packet(packet, additional, socket)

                    distance = calculate_distance(RUSHLocation(x=self._location_x, y=self._location_y), RUSHLocation(raw_data[12:]))

                    self._RIP_Table[self._assigned_IP] = [distance, self._IP, self._assigned_IP, socket, "Switch"]


                    self._indegree_IP[self._assigned_IP]= address[1]
                    self._assigned_IP = ""
                    self._indegree_socket.append(connect)

                if mode == DISTANCE:

                    target_ip = int_to_ip(bytes_to_int(raw_data[12:16]))
                    distance = bytes_to_int(raw_data[16:])
                    if distance <= 1000:
                        if target_ip in self._RIP_Table.keys():
                            if self._RIP_Table[target_ip][0] > distance:
                                self._RIP_Table[target_ip] = [distance, int_to_ip(packet.getfieldval("destination_ip")), int_to_ip(packet.getfieldval("source_ip")), socket, "Switch"]

                                # 广播更新最短路径
                                ip_checklist = [int_to_ip(packet.getfieldval("source_ip")), int_to_ip(packet.getfieldval("destination_ip")), target_ip]

                                self.lock.acquire()
                                for key, val in self._RIP_Table.items():
                                    # 向邻居广播新的DISTANCE包
                                    if ((key == val[2]) and (key not in ip_checklist) ):
                                        pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (target_ip, (distance + val[0])))
                                        self.send_TCP_packet(pkt, additional, val[3])
                                self.lock.release()
                        else:
                            self._RIP_Table[target_ip] = [distance, int_to_ip(packet.getfieldval("destination_ip")), int_to_ip(packet.getfieldval("source_ip")), socket, "Switch"]

                            ip_checklist = [int_to_ip(packet.getfieldval("source_ip")), int_to_ip(packet.getfieldval("destination_ip")), target_ip]
                            
                            # 广播更新最短路径
                            self.lock.acquire()
                            for key, val in self._RIP_Table.items():
                                # 向邻居广播新的DISTANCE包
                                if ((key == val[2]) and (key not in ip_checklist) ):
                                    pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (target_ip, (distance + val[0])))
                                    self.send_TCP_packet(pkt, additional, val[3])
                            self.lock.release()
                    
                # 收到QUERY包
                if mode == QUERY:
                    pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), 0x000000, AVAILABLE)
                    self.send_TCP_packet(pkt, additional, socket)


                # 收到AVAILABLE包
                if mode == AVAILABLE:
                    if (datetime.now() - self.time).seconds < 5:
                        self.lock.acquire()

                        aim_ip = int_to_ip(bytes_to_int(raw_data[:4]))
                        for message in self._DATA:
                            pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), self._start_position, DATA, self._DATA[0])
                            # 判断应该发送给Adapter还是Switch
                            if aim_ip in self._RIP_Table.keys():
                                self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                            else:
                                ip = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                                self.send_TCP_packet(pkt, additional, self._RIP_Table[ip][3])
                            if len(self._DATA) > 1:
                                self._start_position = len(self._DATA[0])
                            else:
                                self._start_position = None
                            self._DATA.pop(0)

                        self.lock.release()


                # 收到DATA包
                if mode == DATA:
                    message = left_info.decode('utf-8')
                    self.time = datetime.now()
                    # 切割data包
                    if len(message) > 1488:
                        while len(message) > 1488:
                            self._DATA.append(message[:1488])
                            message = message[1488:]
                    else:
                        self._DATA.append(message)
                        self._start_position = 0

                    aim_ip = int_to_ip(bytes_to_int(raw_data[4:8]))
                    source_ip = int_to_ip(bytes_to_int(raw_data[:4]))

                    # 如果包的目标地址是自己
                    if aim_ip == self._IP:
                        sys.stdout.write('Received from ' + source_ip + ': ' + left_info.decode('utf-8') + '\n')
                        sys.stdout.flush()
                    

                    # 如果包的目的地址存储在RIP Table中
                    elif aim_ip in self._RIP_Table.keys():
                        pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                    else:
                        target = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                        pkt, additional = build_packet(source_ip, target, 0x000000, QUERY)
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[target][3])


            except:
                break


    # TCP 接收端
    # Greeting - TCP
    def TCP_greeting(self):
        while True:
            self.receive()

    
    # TCP 发送端:
    # 检查input输入并建立相应TCP连接
    def commandline_interface(self):
        port_num = str(self._TCP_socket_reseve.getsockname()[1])
        # sys.stdout.write(port_num + "\n" + "> ")
        # sys.stdout.flush()
        print(port_num)
        while True:

            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError as e:
                print("Something wrong occurred")
                return
            else:
                self.handling_input(user_input)


    # TCP 发送端:
    # 对用户的input进行操作
    def handling_input(self, user_input):
        user_input_split = user_input.split(maxsplit=2) # prevent splitting data
        (connect, send) = (False, False)
        if len(user_input_split) == 2:
            command = user_input_split[0]
            destination_port = user_input_split[1]
            connect = True
        elif len(user_input_split) == 3:
            command = user_input_split[0]
            destination_port = user_input_split[1]
            data = user_input_split[2]
            send = True
        else:
            return
        # Create packet and send

        if connect and command == "connect":
            time.sleep(0.3)     # 我也不知道为啥要设置0.3秒延迟
            # 开启一个线程来建立TCP连接
            TCP_connection = threading.Thread(target=self.TCP_connection, args=(int(destination_port),))
            TCP_connection.start()


    # TCP 发送端:
    # TCP 连接监听并发包
    def TCP_connection(self, destination_port):
        TCP_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCP_socket.connect((LOCAL_HOST, destination_port))
        # 创建DISCOVERY包
        packet, additional = build_packet("0.0.0.0", "0.0.0.0", 0x000000, DISCOVERY, "0.0.0.0")
        self.send_TCP_packet(packet, additional, TCP_socket)

        while True:
            try:
                raw_data = TCP_socket.recv(1024)
                mode = raw_data[11]
                packet = RUSH(raw_data[:12])
                left_info = raw_data[12:]

                # 收到OFFER之后:
                if mode == OFFER:
                    self._destination_IP = str(ipaddress.IPv4Address(raw_data[:4]))
                    self._distributed_IP = str(ipaddress.IPv4Address(int.from_bytes(raw_data[12:16], byteorder='big')))
                    packet, additional = build_packet("0.0.0.0", self._destination_IP, 0x000000, REQUEST, self._distributed_IP)
                    self.send_TCP_packet(packet, additional, TCP_socket)

                # 收到ACKNOWLEDGE包后
                if mode == ACKNOWLEDGE:
                    packet, additional = build_packet(self._distributed_IP, self._destination_IP, 0x000000, LOCATION, (self._location_x, self._location_y))
                    self.send_TCP_packet(packet, additional, TCP_socket)


                # TCP 发送端:
                # 收到LOCATION包后
                if mode == LOCATION:
                    distance = calculate_distance(RUSHLocation(x=self._location_x, y=self._location_y), RUSHLocation(raw_data[12:]))

                    if self._RIP_Table:
                        self.lock.acquire()
                        
                        # 发送端开始发送广播
                        for key, val in self._RIP_Table.items():
                            # 向邻居广播新的DISTANCE包
                            if (key == val[2] and key != self._destination_IP):
                                pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (self._destination_IP, (distance + val[0])))
                                self.send_TCP_packet(pkt, additional, val[3])

                        self.lock.release()
                        self._RIP_Table[int_to_ip(packet.getfieldval("source_ip"))] = [distance, self._distributed_IP, self._destination_IP, TCP_socket, "Switch"]

                    else:
                        self._RIP_Table[int_to_ip(packet.getfieldval("source_ip"))] = [distance, self._distributed_IP, self._destination_IP, TCP_socket, "Switch"]


                    self._outdegree_IP[self._destination_IP] = destination_port
                    self._outdegree_socket.append(TCP_socket)
                    self._distributed_IP = ""
                    self._destination_IP = ""



                # TCP 发送端:
                # 收到DISTANCE包后
                if mode == DISTANCE:

                    target_ip = int_to_ip(bytes_to_int(raw_data[12:16]))
                    distance = bytes_to_int(raw_data[16:])
                    if distance <= 1000:
                        if target_ip in self._RIP_Table.keys():
                            if self._RIP_Table[target_ip][0] > distance:
                                self._RIP_Table[target_ip] = [distance, int_to_ip(packet.getfieldval("destination_ip")), int_to_ip(packet.getfieldval("source_ip")), socket, "Switch"]

                                # 广播更新最短路径
                                ip_checklist = [int_to_ip(packet.getfieldval("source_ip")), int_to_ip(packet.getfieldval("destination_ip")), target_ip]
                                
                                self.lock.acquire()
                                for key, val in self._RIP_Table.items():
                                    # 向邻居广播新的DISTANCE包
                                    if ((key == val[2]) and (key not in ip_checklist) ):
                                        pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (target_ip, (distance + val[0])))
                                        self.send_TCP_packet(pkt, additional, val[3])
                                self.lock.release()
                        else:
                            self._RIP_Table[target_ip] = [distance, int_to_ip(packet.getfieldval("destination_ip")), int_to_ip(packet.getfieldval("source_ip")), socket, "Switch"]

                            ip_checklist = [int_to_ip(packet.getfieldval("source_ip")), int_to_ip(packet.getfieldval("destination_ip")), target_ip]

                            self.lock.acquire()
                            # 广播更新最短路径
                            for key, val in self._RIP_Table.items():
                                # 向邻居广播新的DISTANCE包
                                if ((key == val[2]) and (key not in ip_checklist) ):
                                    pkt, additional = build_packet(val[1], val[2], 0x000000, DISTANCE, (target_ip, (distance + val[0])))
                                    self.send_TCP_packet(pkt, additional, val[3])
                            self.lock.release()
                
                
                # 收到QUERY包
                if mode == QUERY:
                    pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), 0x000000, AVAILABLE)
                    self.send_TCP_packet(pkt, additional, TCP_socket)


                # 收到AVAILABLE包
                if mode == AVAILABLE:
                    if (datetime.now() - self.time).seconds < 5:
                        self.lock.acquire()

                        aim_ip = int_to_ip(bytes_to_int(raw_data[:4]))
                        for message in self._DATA:
                            pkt, additional = build_packet(int_to_ip(bytes_to_int(raw_data[4:8])), int_to_ip(bytes_to_int(raw_data[:4])), self._start_position, DATA, self._DATA[0])
                            # 判断应该发送给Adapter还是Switch

                            if aim_ip in self._RIP_Table.keys():
                                self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                            else:
                                ip = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                                self.send_TCP_packet(pkt, additional, self._RIP_Table[ip][3])
                            if len(self._DATA) > 1:
                                self._start_position = len(self._DATA[0])
                            else:
                                self._start_position = None
                            self._DATA.pop(0)

                        self.lock.release()


                # 收到DATA包
                if mode == DATA:
                    message = left_info.decode('utf-8')
                    self.time = datetime.now()
                    # 切割data包
                    if len(message) > 1488:
                        while len(message) > 1488:
                            self._DATA.append(message[:1488])
                            message = message[1488:]
                    else:
                        self._DATA.append(message)
                        self._start_position = 0

                    aim_ip = int_to_ip(bytes_to_int(raw_data[4:8]))
                    source_ip = int_to_ip(bytes_to_int(raw_data[:4]))

                    # 如果包的目标地址是自己
                    if aim_ip == self._IP:
                        sys.stdout.write('Received from ' + source_ip + ': ' + left_info.decode('utf-8') + '\n')
                        sys.stdout.flush()
                    

                    # 如果包的目的地址存储在RIP Table中
                    elif aim_ip in self._RIP_Table.keys():
                        pkt, additional = build_packet(source_ip, aim_ip, 0x000000, QUERY)
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[aim_ip][3])
                    else:
                        target = longest_prefix_matching(aim_ip, self._RIP_Table.keys())
                        pkt, additional = build_packet(source_ip, target, 0x000000, QUERY)
                        self.send_TCP_packet(pkt, additional, self._RIP_Table[target][3])
            except:
                break



def main(argv):
    
    if len(argv) == 5:
        if argv[1] == "local":
            switch = PureLocalSwitch(argv[1], argv[2], argv[3], argv[4])
            thread1 = threading.Thread(target=switch.UDP_greeting)                  # 用来分配IP池（UDP）
            thread2 = threading.Thread(target=switch.commandline_interface)         # 用来检查用户输入text（TCP）
            thread1.start()
            thread2.start()
            
        elif argv[1] == "global":
            switch = PureGlobalSwitch(argv[1], argv[2], argv[3], argv[4])
            thread1 = threading.Thread(target=switch.TCP_greeting)                  # 用来分配IP池（TCP）
            thread2 = threading.Thread(target=switch.commandline_interface)         # 用来检查用户输入text（TCP）
            thread1.start()
            thread2.start()

    if len(argv) == 6:
        switch = LocalGlobalSwitch(argv[1], argv[2], argv[3], argv[4], argv[5])     
        thread1 = threading.Thread(target=switch.UDP_greeting)                      # 用来分配IP池（UDP）
        thread2 = threading.Thread(target=switch.TCP_greeting)                      # 用来分配IP池（TCP）
        thread1.start()
        thread2.start()




if __name__ == "__main__":
    main(sys.argv)
