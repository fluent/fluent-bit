'''
 /* Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
'''
import select
import socket
import queue
from time import sleep
import struct
import threading
import time
from ctypes import *
import json
import logging
import os

attr_type_list =  [
    "ATTR_TYPE_BYTE", # = ATTR_TYPE_INT8
    "ATTR_TYPE_SHORT",# = ATTR_TYPE_INT16
    "ATTR_TYPE_INT", # = ATTR_TYPE_INT32
    "ATTR_TYPE_INT64",
    "ATTR_TYPE_UINT8",
    "ATTR_TYPE_UINT16",
    "ATTR_TYPE_UINT32",
    "ATTR_TYPE_UINT64",
    "ATTR_TYPE_FLOAT",
    "ATTR_TYPE_DOUBLE",
    "ATTR_NONE",
    "ATTR_NONE",
    "ATTR_TYPE_BOOLEAN",
    "ATTR_TYPE_STRING",
    "ATTR_TYPE_BYTEARRAY"
]


Phase_Non_Start = 0
Phase_Leading = 1
Phase_Type = 2
Phase_Size = 3
Phase_Payload = 4



class imrt_link_message(object):
    def __init__(self):
        self.leading = bytes([0x12, 0x34])
        self.phase = Phase_Non_Start
        self.size_in_phase = 0
        self.message_type = bytes()
        self.message_size = bytes()
        self.payload = bytes()
        self.msg = bytes()

    def set_recv_phase(self, phase):
        self.phase = phase

    def on_imrt_link_byte_arrive(self, ch):
        self.msg += ch
        if self.phase == Phase_Non_Start:
            if ch == b'\x12':
                self.set_recv_phase(Phase_Leading)
            else:
                return -1
        elif self.phase == Phase_Leading:
            if ch == b'\x34':
                self.set_recv_phase(Phase_Type)
            else:
                self.set_recv_phase(Phase_Non_Start)
                return -1
        elif self.phase == Phase_Type:
            self.message_type += ch
            self.size_in_phase += 1

            if self.size_in_phase == 2:
                (self.message_type, ) = struct.unpack('!H', self.message_type)
                self.size_in_phase = 0
                self.set_recv_phase(Phase_Size)
        elif self.phase == Phase_Size:
            self.message_size += ch
            self.size_in_phase += 1

            if self.size_in_phase == 4:
                (self.message_size, ) = struct.unpack('!I', self.message_size)
                self.size_in_phase = 0
                self.set_recv_phase(Phase_Payload)

                if self.message_size == b'\x00':
                    self.set_recv_phase(Phase_Non_Start)
                    return 0

                self.set_recv_phase(Phase_Payload)

        elif self.phase == Phase_Payload:
            self.payload += ch
            self.size_in_phase += 1

            if self.size_in_phase == self.message_size:
                self.set_recv_phase(Phase_Non_Start)
                return 0

            return 2

        return 1



def read_file_to_buffer(file_name):
    file_object = open(file_name, 'rb')
    buffer = None

    if not os.path.exists(file_name):
        logging.error("file {} not found.".format(file_name))
        return "file not found"

    try:
        buffer = file_object.read()
    finally:
        file_object.close()

    return buffer

def decode_attr_container(msg):

    attr_dict = {}

    buf = msg[26 : ]
    (total_len, tag_len) = struct.unpack('@IH', buf[0 : 6])
    tag_name = buf[6 : 6 + tag_len].decode()
    buf = buf[6 + tag_len : ]
    (attr_num, ) = struct.unpack('@H', buf[0 : 2])
    buf = buf[2 : ]

    logging.info("parsed attr:")
    logging.info("total_len:{}, tag_len:{}, tag_name:{}, attr_num:{}"
            .format(str(total_len), str(tag_len), str(tag_name), str(attr_num)))

    for i in range(attr_num):
        (key_len, ) = struct.unpack('@H', buf[0 : 2])
        key_name = buf[2 : 2 + key_len - 1].decode()
        buf = buf[2 + key_len : ]
        (type_index, ) = struct.unpack('@c', buf[0 : 1])

        attr_type = attr_type_list[int(type_index[0])]
        buf = buf[1 : ]

        if attr_type == "ATTR_TYPE_BYTE": # = ATTR_TYPE_INT8
            (attr_value, ) = struct.unpack('@c', buf[0 : 1])
            buf = buf[1 : ]
            # continue
        elif attr_type == "ATTR_TYPE_SHORT": # = ATTR_TYPE_INT16
            (attr_value, ) = struct.unpack('@h', buf[0 : 2])
            buf = buf[2 : ]
            # continue
        elif attr_type == "ATTR_TYPE_INT": # = ATTR_TYPE_INT32
            (attr_value, ) = struct.unpack('@i', buf[0 : 4])
            buf = buf[4 : ]
            # continue
        elif attr_type == "ATTR_TYPE_INT64":
            (attr_value, ) = struct.unpack('@q', buf[0 : 8])
            buf = buf[8 : ]
            # continue
        elif attr_type == "ATTR_TYPE_UINT8":
            (attr_value, ) = struct.unpack('@B', buf[0 : 1])
            buf = buf[1 : ]
            # continue
        elif attr_type == "ATTR_TYPE_UINT16":
            (attr_value, ) = struct.unpack('@H', buf[0 : 2])
            buf = buf[2 : ]
            # continue
        elif attr_type == "ATTR_TYPE_UINT32":
            (attr_value, ) = struct.unpack('@I', buf[0 : 4])
            buf = buf[4 : ]
            # continue
        elif attr_type == "ATTR_TYPE_UINT64":
            (attr_value, ) = struct.unpack('@Q', buf[0 : 8])
            buf = buf[8 : ]
            # continue
        elif attr_type == "ATTR_TYPE_FLOAT":
            (attr_value, ) = struct.unpack('@f', buf[0 : 4])
            buf = buf[4 : ]
            # continue
        elif attr_type == "ATTR_TYPE_DOUBLE":
            (attr_value, ) = struct.unpack('@d', buf[0 : 8])
            buf = buf[8 : ]
            # continue
        elif attr_type == "ATTR_TYPE_BOOLEAN":
            (attr_value, ) = struct.unpack('@?', buf[0 : 1])
            buf = buf[1 : ]
            # continue
        elif attr_type == "ATTR_TYPE_STRING":
            (str_len, ) = struct.unpack('@H', buf[0 : 2])
            attr_value = buf[2 : 2 + str_len - 1].decode()
            buf = buf[2 + str_len : ]
            # continue
        elif attr_type == "ATTR_TYPE_BYTEARRAY":
            (byte_len, ) = struct.unpack('@I', buf[0 : 4])
            attr_value = buf[4 : 4 + byte_len]
            buf = buf[4 + byte_len : ]
            # continue

        attr_dict[key_name] = attr_value

    logging.info(str(attr_dict))
    return attr_dict

class Request():
    mid = 0
    url = ""
    action = 0
    fmt = 0
    payload = ""
    payload_len = 0
    sender = 0

    def __init__(self, url, action, fmt, payload, payload_len):
        self.url = url
        self.action = action
        self.fmt = fmt
        # if type(payload) == bytes:
        #     self.payload = bytes(payload, encoding = "utf8")
        # else:
        self.payload_len = payload_len
        if self.payload_len > 0:
            self.payload = payload
        
    
    def pack_request(self):
        url_len = len(self.url) + 1
        buffer_len = url_len + self.payload_len

        req_buffer = struct.pack('!2BH2IHI',1, self.action, self.fmt, self.mid, self.sender, url_len, self.payload_len)
        for i in range(url_len - 1):
            req_buffer += struct.pack('!c', bytes(self.url[i], encoding = "utf8"))
        req_buffer += bytes([0])
        for i in range(self.payload_len):
            req_buffer += struct.pack('!B', self.payload[i])    

        return req_buffer, len(req_buffer)


    def send(self, conn, is_install):
        leading = struct.pack('!2B', 0x12, 0x34)
        
        if not is_install:
            msg_type = struct.pack('!H', 0x0002)
        else:
            msg_type = struct.pack('!H', 0x0004)
        buff, buff_len = self.pack_request()
        lenth = struct.pack('!I', buff_len)

        try:
            conn.send(leading)
            conn.send(msg_type)
            conn.send(lenth)
            conn.send(buff)
        except socket.error as e:
            logging.error("device closed")
            for dev in tcpserver.devices:
                if dev.conn == conn:
                    tcpserver.devices.remove(dev)
            return -1
            

def query(conn):
    req = Request("/applet", 1, 0, "", 0)
    if req.send(conn, False) == -1:
        return "fail"
    time.sleep(0.05)
    try:
        receive_context = imrt_link_message()
        start = time.time()
        while True:
            if receive_context.on_imrt_link_byte_arrive(conn.recv(1)) == 0:
                break
            elif time.time() - start >= 5.0:
                return "fail"
        query_resp = receive_context.msg
        print(query_resp)
    except OSError as e:
        logging.error("OSError exception occur")
        return "fail"

    res = decode_attr_container(query_resp)

    logging.info('Query device infomation success')
    return res

def install(conn, app_name, wasm_file):
    wasm = read_file_to_buffer(wasm_file)
    if wasm == "file not found":
        return "failed to install: file not found"
        
    print("wasm file len:")
    print(len(wasm))
    req = Request("/applet?name=" + app_name, 3, 98, wasm, len(wasm))
    if req.send(conn, True) == -1:
        return "fail"
    time.sleep(0.05)
    try:
        receive_context = imrt_link_message()
        start = time.time()
        while True:
            if receive_context.on_imrt_link_byte_arrive(conn.recv(1)) == 0:
                break
            elif time.time() - start >= 5.0:
                return "fail"
        msg = receive_context.msg
    except OSError as e:
        logging.error("OSError exception occur")
    # TODO: check return message

    if len(msg) == 24 and msg[8 + 1] == 65:
        logging.info('Install application success')
        return "success"
    else:
        res = decode_attr_container(msg)
        logging.warning('Install application failed: %s' % (str(res)))
        print(str(res))

        return str(res)
    

def uninstall(conn, app_name):
    req = Request("/applet?name=" + app_name, 4, 99, "", 0)
    if req.send(conn, False) == -1:
        return "fail"
    time.sleep(0.05)
    try:
        receive_context = imrt_link_message()
        start = time.time()
        while True:
            if receive_context.on_imrt_link_byte_arrive(conn.recv(1)) == 0:
                break
            elif time.time() - start >= 5.0:
                return "fail"
        msg = receive_context.msg
    except OSError as e:
        logging.error("OSError exception occur")
    # TODO: check return message

    if len(msg) == 24 and msg[8 + 1] == 66:
        logging.info('Uninstall application success')
        return "success"
    else:
        res = decode_attr_container(msg)
        logging.warning('Uninstall application failed: %s' % (str(res)))
        print(str(res))

        return str(res)

class Device:
    def __init__(self, conn, addr, port):
        self.conn = conn
        self.addr = addr
        self.port = port
        self.app_num = 0
        self.apps = []

cmd = []

class TCPServer:
    def __init__(self, server, server_address, inputs, outputs, message_queues):
        # Create a TCP/IP
        self.server = server
        self.server.setblocking(False)

        # Bind the socket to the port
        self.server_address = server_address
        print('starting up on %s port %s' % self.server_address)
        self.server.bind(self.server_address)

        # Listen for incoming connections
        self.server.listen(10)

        self.cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cmd_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        self.cmd_sock.bind(('127.0.0.1', 8889))
        self.cmd_sock.listen(5)


        # Sockets from which we expect to read
        self.inputs = inputs
        self.inputs.append(self.cmd_sock)

        # Sockets to which we expect to write
        # 处理要发送的消息
        self.outputs = outputs
        # Outgoing message queues (socket: Queue)
        self.message_queues = message_queues

        self.devices = []
        self.conn_dict = {}

    def handler_recever(self, readable):
        # Handle inputs
        for s in readable:
            if s is self.server:
                # A "readable" socket is ready to accept a connection
                connection, client_address = s.accept()
                self.client_address = client_address
                print('connection from', client_address)
                # this is connection not server
                # connection.setblocking(0)
                self.inputs.append(connection)

                # Give the connection a queue for data we want to send
                # self.message_queues[connection] = queue.Queue()

                res = query(connection)
                
                if res != "fail":
                    dev = Device(connection, client_address[0], client_address[1])
                    self.devices.append(dev)
                    self.conn_dict[client_address] = connection

                    dev_info = {}
                    dev_info['addr'] = dev.addr
                    dev_info['port'] = dev.port
                    dev_info['apps'] = 0

                    logging.info('A new client connected from ("%s":"%s")' % (dev.conn, dev.port))

            elif s is self.cmd_sock:
                connection, client_address = s.accept()
                print("web server socket connected")
                logging.info("Django server connected")
                self.inputs.append(connection)
                self.message_queues[connection] = queue.Queue()

            else:
                data = s.recv(1024)
                if data != b'':
                    # A readable client socket has data
                    logging.info('received "%s" from %s' % (data, s.getpeername()))
                    
                    # self.message_queues[s].put(data)
                    # # Add output channel for response
                   
                    # if s not in self.outputs:
                    #     self.outputs.append(s)
                    
                    if(data.decode().split(':')[0] == "query"):
                        if data.decode().split(':')[1] == "all":
                            resp = []
                            print('start query all devices')
                            for dev in self.devices:
                                dev_info = query(dev.conn)
                                if dev_info == "fail":
                                    continue
                                dev_info["addr"] = dev.addr
                                dev_info["port"] = dev.port
                                resp.append(str(dev_info))
                                
                                print(resp)

                            if self.message_queues[s] is not None:
                                # '*' is used in web server to sperate the string
                                self.message_queues[s].put(bytes("*".join(resp), encoding = 'utf8'))
                                if s not in self.outputs:
                                    self.outputs.append(s)
                        else:
                            client_addr = (data.decode().split(':')[1],int(data.decode().split(':')[2]))

                            if client_addr in self.conn_dict.keys():
                                print('start query device from (%s:%s)' % (client_addr[0], client_addr[1]))
                                resp = query(self.conn_dict[client_addr])
                                print(resp)

                                if self.message_queues[s] is not None:
                                    self.message_queues[s].put(bytes(str(resp), encoding = 'utf8'))
                                    if s not in self.outputs:
                                        self.outputs.append(s)
                            else:   # no connection
                                if self.message_queues[s] is not None:
                                    self.message_queues[s].put(bytes(str("fail"), encoding = 'utf8'))
                                    if s not in self.outputs:
                                        self.outputs.append(s)
                    elif(data.decode().split(':')[0] == "install"):
                        client_addr = (data.decode().split(':')[1],int(data.decode().split(':')[2]))
                        app_name = data.decode().split(':')[3]
                        app_file = data.decode().split(':')[4]

                        if client_addr in self.conn_dict.keys():
                            print('start install application %s to ("%s":"%s")' % (app_name, client_addr[0], client_addr[1]))
                            res = install(self.conn_dict[client_addr], app_name, app_file)
                            if self.message_queues[s] is not None:
                                logging.info("response {} to cmd server".format(res))
                                self.message_queues[s].put(bytes(res, encoding = 'utf8'))
                                if s not in self.outputs:
                                    self.outputs.append(s)
                    elif(data.decode().split(':')[0] == "uninstall"):
                        client_addr = (data.decode().split(':')[1],int(data.decode().split(':')[2]))
                        app_name = data.decode().split(':')[3]

                        if client_addr in self.conn_dict.keys():
                            print("start uninstall")
                            res = uninstall(self.conn_dict[client_addr], app_name)
                            if self.message_queues[s] is not None:
                                logging.info("response {} to cmd server".format(res))
                                self.message_queues[s].put(bytes(res, encoding = 'utf8'))
                                if s not in self.outputs:
                                    self.outputs.append(s)


                    # if self.message_queues[s] is not None:
                    #     self.message_queues[s].put(data)
                    #     if s not in self.outputs:
                    #         self.outputs.append(s)
                else:
                    logging.warning(data)
                    
                    # Interpret empty result as closed connection
                    try:
                        for dev in self.devices:
                            if s == dev.conn:
                                self.devices.remove(dev)
                        # Stop listening for input on the connection
                        if s in self.outputs:
                            self.outputs.remove(s)
                        self.inputs.remove(s)

                        # Remove message queue
                        if s in self.message_queues.keys():
                            del self.message_queues[s]
                        s.close()
                    except OSError as e:
                        logging.error("OSError raised, unknown connection")
            return "got it"

    def handler_send(self, writable):
        # Handle outputs
        for s in writable:
            try:
                message_queue = self.message_queues.get(s)
                send_data = ''
                if message_queue is not None:
                    send_data = message_queue.get_nowait()
            except queue.Empty:
                self.outputs.remove(s)
            else:
                # print "sending %s to %s " % (send_data, s.getpeername)
                # print "send something"
                if message_queue is not None:
                    s.send(send_data)
                else:
                    print("client has closed")
                # del message_queues[s]
                # writable.remove(s)
                # print "Client %s disconnected" % (client_address)
            return "got it"

    def handler_exception(self, exceptional):
        # # Handle "exceptional conditions"
        for s in exceptional:
            print('exception condition on', s.getpeername())
            # Stop listening for input on the connection
            self.inputs.remove(s)
            if s in self.outputs:
                self.outputs.remove(s)
            s.close()

            # Remove message queue
            del self.message_queues[s]
            return "got it"


def event_loop(tcpserver, inputs, outputs):
    while inputs:
        # Wait for at least one of the sockets to be ready for processing
        print('waiting for the next event')
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        if readable is not None:
            tcp_recever = tcpserver.handler_recever(readable)
            if tcp_recever == 'got it':
                print("server have received")
        if writable is not None:
            tcp_send = tcpserver.handler_send(writable)
            if tcp_send == 'got it':
                print("server have send")
        if exceptional is not None:
            tcp_exception = tcpserver.handler_exception(exceptional)
            if tcp_exception == 'got it':
                print("server have exception")


        sleep(0.1)

def run_wasm_server():
    server_address = ('localhost', 8888)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    inputs = [server]
    outputs = []
    message_queues = {}
    tcpserver = TCPServer(server, server_address, inputs, outputs, message_queues)
    
    task = threading.Thread(target=event_loop,args=(tcpserver,inputs,outputs))
    task.start()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                    filename='wasm_server.log',
                    filemode='a',
                    format=
                    '%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'
                    )
    server_address = ('0.0.0.0', 8888)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    inputs = [server]
    outputs = []
    message_queues = {}
    tcpserver = TCPServer(server, server_address, inputs, outputs, message_queues)
    logging.info("TCP Server start at {}:{}".format(server_address[0], "8888"))
    
    task = threading.Thread(target=event_loop,args=(tcpserver,inputs,outputs))
    task.start()
    
    # event_loop(tcpserver, inputs, outputs)    