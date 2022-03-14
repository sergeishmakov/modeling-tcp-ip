from typing import List


class TCP_IP:
    def __init__(self, transfer_file_path: str, TTL: int, 
                 ip_source: str, ip_destination: str,
                 port_source: int, port_destination: int):

        self._transfer_file_path: str = transfer_file_path

        self._ip_version: str = '{0:b}'.format(4).zfill(4)
        self._IHL: str = '{0:b}'.format(5).zfill(4)
        self._DSCP: str = '{0:b}'.format(0).zfill(6)
        self._ECN: str = '{0:b}'.format(0).zfill(2)
        self._headers_size: int = 20 + 20

        self._identifier: int  = 0
        self._reserved_flag: str = '{0:b}'.format(0).zfill(1)
        self._no_fragmentation: str = '{0:b}'.format(1).zfill(1)
        self._is_exists_fragment: str = '{0:b}'.format(0).zfill(1)
        self._fragment_offset: str = '{0:b}'.format(0).zfill(13)

        self._TTL: int = TTL
        self._protocol: int = 6
        self._ip_checksum: int = 0

        self._ip_source: List[int] = [int(octet) for octet in ip_source.split('.')]
        self._ip_destination: List[int] = [int(octet) for octet in ip_destination.split('.')]

        self._port_source: int = port_source
        self._port_destination: int = port_destination

        self._sequence_number: int = 0
        self._acknowledgment_number: int = 0

        self._data_offset: str = '{0:b}'.format(5).zfill(4)
        self._reserved: str = '{0:b}'.format(0).zfill(6)
        self._URG: str = '{0:b}'.format(0).zfill(1)
        self._ACK: str = '{0:b}'.format(0).zfill(1)
        self._PSH: str = '{0:b}'.format(0).zfill(1)
        self._RST: str = '{0:b}'.format(0).zfill(1)
        self._SYN: str = '{0:b}'.format(0).zfill(1)
        self._FIN: str = '{0:b}'.format(0).zfill(1)
        self._window_size: int = 0

        self._tcp_checksum: int = 0
        self._urgent_point: int = 0

    def _build_package(self, data_package: bytes,
                       ip_checksum: int,
                       tcp_checksum: int,
                       sequence_number: int) -> List[bytes]:

        package: List[bytes] = []
        package_size: int = self._headers_size + len(data_package)

        package.append(int(self._ip_version + self._IHL, 2).to_bytes(1, byteorder='big'))
        package.append(int(self._DSCP + self._ECN, 2).to_bytes(1, byteorder='big'))
        package.append((package_size).to_bytes(2, byteorder='big'))
        package.append((self._identifier).to_bytes(2, byteorder='big'))
        package.append(int(self._reserved_flag + self._no_fragmentation + 
                           self._is_exists_fragment + 
                           self._fragment_offset, 2).to_bytes(2, byteorder='big'))
        
        package.append((self._TTL).to_bytes(1, byteorder='big'))
        package.append((self._protocol).to_bytes(1, byteorder='big'))
        package.append((ip_checksum).to_bytes(2, byteorder='big'))

        for octet in self._ip_source:
            package.append(bytes([octet]))

        for octet in self._ip_destination:
            package.append(bytes([octet]))

        package.append((self._port_source).to_bytes(2, byteorder='big'))
        package.append((self._port_destination).to_bytes(2, byteorder='big'))

        package.append((sequence_number).to_bytes(4, byteorder='big'))
        package.append((self._acknowledgment_number).to_bytes(4, byteorder='big'))

        package.append(int(self._data_offset + self._reserved + 
                           self._URG + self._ACK + self._PSH + self._RST +
                           self._SYN + self._FIN, 2).to_bytes(2, byteorder='big'))
        package.append((self._window_size).to_bytes(2, byteorder='big'))

        package.append((tcp_checksum).to_bytes(2, byteorder='big'))
        package.append((self._urgent_point).to_bytes(2, byteorder='big'))

        package.append(data_package)

        return package

    def _compute_checksum(self, package: List[bytes]) -> tuple:
        union_bytes: bytes = bytes()
        sum_ip_list: List[int] = []
        sum_tcp_list: List[int] = []

        for bytes_ in package:
            union_bytes += bytes_

        for ind in range(0, 20, 2):
            binary_value: str = '{0:b}'.format(union_bytes[ind]).zfill(8) + '{0:b}'.format(union_bytes[ind + 1]).zfill(8)
            sum_ip_list.append(int(binary_value, 2))

        for ind in range(20, len(union_bytes), 2):
            binary_value: str = '{0:b}'.format(union_bytes[ind]).zfill(8) + '{0:b}'.format(union_bytes[ind + 1]).ljust(8, '0')
            sum_tcp_list.append(int(binary_value, 2))

        ip_checksum: int = sum(sum_ip_list) & 0xFFFF
        tcp_checksum: int = sum(sum_tcp_list) & 0xFFFF
        
        return ip_checksum, tcp_checksum

    def _create_ip_packages(self, payload_size: int, work_folder: str) -> None:
        if payload_size > 2 ** 16 - self._headers_size:
            raise 'Payload size too big.'
        else:
            with open(f'{work_folder}/{self._transfer_file_path}', 'rb') as transfer:
                data: bytes = transfer.read()
                data_batch_size: int = payload_size - 20 - 20
                package_number: int = 1

                for ind in range(0, len(data), data_batch_size):
                    initial_package: List[bytes] = self._build_package(data_package=data[ind:ind + data_batch_size],
                                                                    ip_checksum=self._ip_checksum,
                                                                    tcp_checksum=self._tcp_checksum,
                                                                    sequence_number=ind)

                    ip_checksum, tcp_checksum = self._compute_checksum(initial_package)

                    package: List[bytes] = self._build_package(data_package=data[ind:ind + data_batch_size],
                                                            ip_checksum=ip_checksum,
                                                            tcp_checksum=tcp_checksum,
                                                            sequence_number=ind)

                    with open(f'{work_folder}/000{package_number}.ip', 'wb') as ip_package:
                        for bytes_ in package:
                            ip_package.write(bytes_)

                    package_number += 1

    def create_ip_packages(self, payload_size: int, work_folder: str) -> None:
        self._create_ip_packages(payload_size, work_folder)
