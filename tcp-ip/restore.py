import os

import numpy as np
from typing import List


class RestoreData:
    def _binary_array2int(self, binary_array: np.ndarray) -> int:
            result: int = 0

            for i, j in enumerate(binary_array[::-1]):
                result += j << i

            return result

    def _ip_packages_order(self, work_folder: str) -> dict:
            ip_packages_names: List[str] = []
            packages_sequence_numbers: dict = {}

            for file_name in os.listdir(f'{work_folder}'):
                if file_name.endswith('.ip'):
                    ip_packages_names.append(file_name)
                else:
                    continue
            
            for ip_package in ip_packages_names:
                bytes_: bytes = np.fromfile(f'{work_folder}/{ip_package}', dtype='uint8')
                bits: np.ndarray = np.unpackbits(bytes_)
                ip_header_len: int = self._binary_array2int(bits[4:8]) * 32
                sequence_number_start_bit: int = ip_header_len + 16 + 16 
                sequence_number_bit: np.ndarray = bits[sequence_number_start_bit: sequence_number_start_bit + 32]
                sequence_number: int = self._binary_array2int(sequence_number_bit)
                packages_sequence_numbers[ip_package] = sequence_number
            
            return dict(sorted(packages_sequence_numbers.items(), key=lambda item: item[1]))

    def _data_restore(self, work_folder:str, restore_file_name: str) -> None:
        ip_packages_order: dict = self._ip_packages_order(work_folder)
        restore_full_path: str = f'{work_folder}/{restore_file_name}'

        if os.path.exists(restore_full_path):
            os.remove(restore_full_path)

        for ip_package in ip_packages_order.keys():
            bytes_: bytes = np.fromfile(f'{work_folder}/{ip_package}', dtype='uint8')
            bits: np.ndarray = np.unpackbits(bytes_)
            ip_header_len: int = self._binary_array2int(bits[4:8]) * 32

            data_offset_start: int = ip_header_len + 16 + 16 + 32 + 32
            tcp_header_len: int = self._binary_array2int(bits[data_offset_start:data_offset_start + 4]) * 32
            
            with open(f'{work_folder}/{ip_package}', 'rb') as pack:
                data_start: int = int((ip_header_len + tcp_header_len) / 8)
                restote_data: bytes = pack.read()[data_start:]

                with open(f'{work_folder}/{restore_file_name}', 'ab') as restore:
                    restore.write(restote_data)

    def data_restore(self, work_folder:str, restore_file_name: str) -> None:
        self._data_restore(work_folder, restore_file_name)
