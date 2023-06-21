
import threading
import os
import socket
import argparse
import logging


def connection_scan(target_ip, target_port):
    """Attempt to create a socket connection with the given IP address and port.
    If successful, port is open; if not, port is closed."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn_socket:
            conn_socket.settimeout(2)  # Set timeout for the connection attempt
            result = conn_socket.connect_ex((target_ip, target_port))
            if result == 0:
                logging.info("[+] {}/tcp open".format(target_port))
            else:
                logging.info("[-] {}/tcp closed".format(target_port))
    except OSError as e:
        logging.error("[-] An error occurred: {}".format(e))


def port_scan(target, port_list):
    """Scan indicated ports for status.
    First, attempt to resolve the IP address of a provided hostname, then enumerate through the ports."""
    try:
        target_ip = socket.gethostbyname(target)
        logging.info('[*] Scan Results for: {}'.format(target_ip))
        for port in port_list:
            connection_scan(target_ip, int(port))
    except socket.gaierror:
        logging.error("[^] Cannot resolve {}: Unknown host".format(target))
    except ValueError:
        logging.error("[-] Invalid port number provided.")


def argument_parser():
    """
    Allow user to specify target host and port.
    """
    parser = argparse.ArgumentParser(description="TCP port scanner. Accepts a hostname/IP address and list of ports "
                                                 "to scan. Attempts to identify the service running on a port.")
    parser.add_argument("-o", "--host", help="Host IP address")
    parser.add_argument("-p", "--ports", help="Comma-separated port list, such as 25,80,8080")

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    logging.basicConfig(filename='port_scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    try:
        user_args = argument_parser()
        host = user_args.host
        port_list = user_args.ports.split(",")
        port_scan(host, port_list)
    except AttributeError:
        print("Error: Please provide the required command-line arguments.")
