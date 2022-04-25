import socket
import sys
from datetime import datetime

PAYLOAD_SIZE = 1464 
STANDARD_FLAGS = {
    'SIMPLE_GET': '0010000',
    'SIMPLE_DAT': '0001000',
    'SIMPLE_FIN': '0000100',
    'DAT_ACK': '1001000',
    'FIN_ACK': '1000100',
    'DAT_NAK': '0101000',
    'GET_CHK': '0010010',
    'CHK_DAT_ACK': '1001010',
    'FIN_CHK': '0000110',
    'CHK_FIN_ACK': '1000110'
}

def compute_checksum(message):
    """copy from file in client.py"""
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):        
        w = b_str[i] + (b_str[i+1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff

def carry_around_add(a, b):
    """copy from file in client.py"""
    c = a + b
    return (c & 0xffff) + (c >> 16)


class RushBService():
    def __init__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 23456))
        self._client_history = {}

    

    def initialize_client(self, address, file, packet, checksum, sequence_num, client_sequence):
        """
            create a client in history, including:
            file he try to read, last packet, check sum status,
            sequence number and client sequence number
        """
        port_num = address[1]
        self._client_history[port_num] = {}
        self._client_history[port_num]['file'] = file
        self._client_history[port_num]['packet'] = packet
        self._client_history[port_num]['checksum'] = checksum
        self._client_history[port_num]['sequence_num'] = sequence_num
        self._client_history[port_num]['client_sequence'] = client_sequence
        self.set_client_time(address)


    def get_client(self, address):
        """get the client in client history"""
        return self._client_history[address[1]]


    def get_file(self, port_num):
        """get the file history of client"""
        return self.get_client(port_num)['file']
    

    def get_checksum(self, port_num):
        """get the checksum information of client"""
        return self.get_client(port_num)['checksum']

    def get_packet(self, port_num):
        """get the packet history of client"""
        return self.get_client(port_num)['packet']
    
    def get_time(self, port_num):
        """get the time history of client"""
        return self.get_client(port_num)['time']
    

    def get_sequence_num(self, port_num):
        """get the sequence number history of client"""
        return self.get_client(port_num)['sequence_num']
    

    def get_client_sequence(self, port_num):
        """get the client sequence history of client"""
        return self.get_client(port_num)['client_sequence']
        
    def set_client_time(self, address):
        """set the client's time of given client port information"""
        self.get_client(address)['time'] = datetime.now()


    def run(self):
        """main service logic"""
        print(self._socket.getsockname()[1], flush=True)

        while True:
            try:
                # receive packet
                data, address = self._socket.recvfrom(1500)
            except:
                for key in self._client_history:
                    client = self._client_history[key]
                    if ((datetime.now() - client['time']).seconds > 4):
                        self.resend_packet((address[0], key))
                continue
            self._socket.settimeout(1)

            sequence_num, ack_num, checksum,\
                ACK, NAK, GET, DAT, FIN, CHK, ENC, flags = RushBService.get_header_information(data)
            # print('port:', address[1],'squence_num:',sequence_num,',ack_num:',ack_num,',checksum:',checksum,',ACK:',\
            #     ACK,',NAK:',NAK,',GET:',GET,',DAT:',DAT,',FIN:',FIN,',CHK:',CHK,',ENC:',ENC,'flags:',flags)

            # check whether checksum flag is valid
            if self._client_history.__contains__(address[1]) \
                and ((CHK == '1' and not self.get_checksum(address)) \
                    or (CHK == '0' and self.get_checksum(address))):
                print('in the loop!')
                continue

            # client send get request
            if (flags == STANDARD_FLAGS['SIMPLE_GET'] and sequence_num == 1 and ack_num == 0):
                file_name = data.rstrip(b'\x00')[8:]
                if (file_name):
                    try:
                        f = open(file_name, 'r')
                        # self._file  = f.read()
                        self.initialize_client(address, f.read(), b'', False, 0, 0)
                        f.close()
                    except IOError:
                        print("Requested file does not exist.")
                        continue
                    self.send_packet_with_data(address, sequence_num)
            # client sent ack data packet
            elif (flags == STANDARD_FLAGS['DAT_ACK']):
                if (sequence_num == self.get_client_sequence(address) + 1 \
                        and ack_num == self.get_sequence_num(address) \
                        and not data.rstrip(b'\x00')[8:]):
                    # after receive a valid packet, reset the time
                    self.set_client_time(address)
                    if (self.get_file(address)):
                        # send next packet to client
                        self.send_packet_with_data(address, sequence_num)
                    else:
                        # request finish to client
                        self.sent_other_packet(address, self.get_sequence_num(address), 0, 0, STANDARD_FLAGS['SIMPLE_FIN'])
                        self.get_client(address)["client_sequence"] = sequence_num
            # client sent ack to finish connection
            elif (flags == STANDARD_FLAGS['FIN_ACK']):
                if (sequence_num == self.get_client_sequence(address) + 1 \
                        and ack_num == self.get_sequence_num(address) \
                        and not data.rstrip(b'\x00')[8:]):
                    # after receive a valid packet, reset the time
                    self.set_client_time(address)
                    self.sent_other_packet(address, self.get_sequence_num(address), sequence_num, 0, STANDARD_FLAGS['FIN_ACK'])
                    self._client_history.pop(address[1])
            # data packet sent to client was lost, resent previous packet
            elif (flags == STANDARD_FLAGS['DAT_NAK']):
                if (sequence_num == self.get_client_sequence(address) + 1 \
                        and ack_num == self.get_sequence_num(address) \
                        and not data.rstrip(b'\x00')[8:]):
                    # after receive a valid packet, reset the time
                    self.set_client_time(address)
                    if self.get_packet(address):
                        self.resend_packet(address)
                        self.get_client(address)['client_sequence'] = sequence_num
            # get request with check 
            elif (flags == STANDARD_FLAGS['GET_CHK']):
                try:
                    if checksum == compute_checksum(data.rstrip(b'\x00')[8:]):
                        file_name = data.rstrip(b'\x00')[8:]
                        if file_name:
                            try:
                                f = open(file_name, 'r')
                                # self._file  = f.read()
                                self.initialize_client(address, f.read(), b'', True, 0, 0)
                                f.close()
                                self.send_checksum_packet(address, sequence_num)
                            except IOError:
                                print("Requested file does not exist.")
                                continue
                except:
                    print('checksum number is wrong')
            # data ack packet with checksum
            elif (flags == STANDARD_FLAGS['CHK_DAT_ACK']):
                if sequence_num == self.get_client_sequence(address) + 1 \
                        and ack_num == self.get_sequence_num(address) \
                        and not data.rstrip(b'\x00')[8:]:
                    if checksum == compute_checksum(data.rstrip(b'\x00')[8:]):
                        # after receive a valid packet, reset the time
                        self.set_client_time(address)
                        if (self.get_file(address)):
                            self.send_checksum_packet(address, sequence_num)
                        else:
                            self.sent_other_packet(address, self.get_sequence_num(address), 0, checksum, STANDARD_FLAGS['FIN_CHK'])
                            self.get_client(address)["client_sequence"] = sequence_num
            # fin request packet with checksum
            elif (flags == STANDARD_FLAGS['CHK_FIN_ACK']):
                if sequence_num == self.get_client_sequence(address) + 1 \
                        and ack_num == self.get_sequence_num(address) \
                        and not data.rstrip(b'\x00')[8:]:
                    # after receive a valid packet, reset the time
                    self.set_client_time(address)
                    self.sent_other_packet(address, self.get_sequence_num(address), sequence_num, checksum, STANDARD_FLAGS['CHK_FIN_ACK'])
                    self._client_history.pop(address[1])

    def sent_other_packet(self, address, sequence_num, ack_num, checksum, flags):
        """send packet except for those with meaningful data and checksum"""
        self.get_client(address)["sequence_num"] += 1
        self.get_client(address)["packet"] = self.create_package(self.get_sequence_num(address), ack_num, checksum, flags)
        self._socket.sendto(self.get_packet(address), address)
    
    
    def send_checksum_packet(self, address, sequence_num):
        """send packet with checksum"""
        self.get_client(address)['sequence_num'] += 1
        checksum = compute_checksum(self.get_file(address)[:PAYLOAD_SIZE].encode('utf-8'))
        self.get_client(address)['packet'] = self.create_package(self.get_sequence_num(address), \
            0, checksum, '0001010', self.get_file(address)[:PAYLOAD_SIZE])
        self.get_client(address)['file'] = self.get_client(address)['file'][PAYLOAD_SIZE:]
        try:
            self._socket.sendto(self.get_packet(address), address)
        except socket.error:
            print('Something wrong in sending data packet after GET and CHK!')
        self.get_client(address)['client_sequence'] = sequence_num


    def resend_packet(self, address):
        """the data packet was lost, resent it"""
        try:
            self._socket.sendto(self.get_packet(address), address)
        except socket.error:
            print('Something wrong when resent packet!')

    
    def send_packet_with_data(self, address, sequence_num):
        """send packet with data to client"""
        self.get_client(address)["sequence_num"] += 1
        self.get_client(address)["packet"] = self.create_package(self.get_sequence_num(address), 0, 0, STANDARD_FLAGS['SIMPLE_DAT'], self.get_file(address)[:PAYLOAD_SIZE])
        self.get_client(address)['file'] = self.get_file(address)[PAYLOAD_SIZE:]
        try:
            self._socket.sendto(self.get_packet(address), address)
        except socket.error:
            print('Something wrong in send packet!')
        self.get_client(address)['client_sequence'] = sequence_num

    

    @staticmethod
    def create_package(sequence_num, ack_num, checksum, flags, file=None):
        """create packet, including header and ASCII payload"""
        header = ''
        header += RushBService.convert_to_bit(sequence_num, 16)
        header += RushBService.convert_to_bit(ack_num, 16)
        header += RushBService.convert_to_bit(checksum, 16)
        header += flags.ljust(13, '0')
        header += bin(0)[2:]
        header += bin(1)[2:]
        header += bin(0)[2:]
        if file:
            # exists meaningful information in payload
            payload = RushBService.convert_file(file).to_bytes(PAYLOAD_SIZE, byteorder='big')
        else:
            # no meaningful information in payload
            payload = (0).to_bytes(PAYLOAD_SIZE, byteorder='big')
        header = bytes([int(header[i:i + 8], 2) for i in range(0, 64, 8)])
        return header + payload


    @staticmethod
    def convert_file(file):
        """convert the given file() to 1464 bytes"""
        result = file.encode("UTF-8")
        if (len(file) < PAYLOAD_SIZE):
            result += (PAYLOAD_SIZE - len(file)) * b'\x00'
        return int.from_bytes(result, byteorder='big')


    @staticmethod
    def get_header_information(message):
        """get the RUSHB HEADER information"""
        header = message.rstrip(b'\x00')
        return RushBService.bit_to_byte(RushBService.get_two_byte_num(header, 0, 1)),\
            RushBService.bit_to_byte(RushBService.get_two_byte_num(header, 2, 3)),\
            RushBService.bit_to_byte(RushBService.get_two_byte_num(header, 4, 5)),\
            RushBService.convert_to_bit(header[6])[0],\
            RushBService.convert_to_bit(header[6])[1],\
            RushBService.convert_to_bit(header[6])[2],\
            RushBService.convert_to_bit(header[6])[3],\
            RushBService.convert_to_bit(header[6])[4],\
            RushBService.convert_to_bit(header[6])[5],\
            RushBService.convert_to_bit(header[6])[6],\
            RushBService.get_two_byte_num(header, 6, 7)[:7]
            


    @staticmethod
    def get_two_byte_num(information, index1, index2):
        """get the number of two bytes"""
        return RushBService.convert_to_bit(information[index1]) +\
             RushBService.convert_to_bit(information[index2])


    @staticmethod
    def convert_to_bit(string, bits=8):
        """contert string or integer to 8 bit"""
        # print("input string is: ", string)
        try:
            return bin(int(string))[2:].zfill(bits)
        except:
            return False

  
    @staticmethod
    def bit_to_byte(bit):
        """contert string or integer to byte"""
        # print("input bit is: ", bit)
        try:
            return int(bit, 2)
        except:
            return False


def main():
    RushBService().run()


if __name__ == '__main__':
    main()