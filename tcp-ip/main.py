import argparse

from tcp_ip import TCP_IP
from restore import RestoreData


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-tfile', type=str, dest='tfile', required=False, help='path to file for transfer')
    parser.add_argument('-work-folder', type=str, dest='work_folder', required=True, help='path to folder for save .ip files')
    parser.add_argument('-mode', type=int, dest='mode', required=True, help='0 - transfer, 1 - restore')
    parser.add_argument('-payload', type=int, dest='payload', required=False, help='payload size in bytes')
    parser.add_argument('-ip-source', type=str, dest='ip_source', required=False, help='ip address of source')
    parser.add_argument('-ip-destination', type=str, dest='ip_destination', required=False, help='ip address of destination')
    parser.add_argument('-port-source', type=int, dest='port_source', required=False, help='port of source')
    parser.add_argument('-port-destination', type=int, dest='port_destination', required=False, help='port of destination')
    parser.add_argument('-ttl', type=int, dest='ttl', required=False, help='ttl value')
    args = parser.parse_args()

    if args.mode == 0:
        package_imitation = TCP_IP(transfer_file_path=args.tfile, TTL=args.ttl,
                                   ip_source=args.ip_source, ip_destination=args.ip_destination,
                                   port_source=args.port_source, port_destination=args.port_destination)
        
        package_imitation.create_ip_packages(args.payload, args.work_folder)
    
    elif args.mode == 1:
        restore = RestoreData()
        restore.data_restore(work_folder=args.work_folder, restore_file_name='ip-data-restore.txt')
    else:
        raise Exception('Selected mode does not exists.')
