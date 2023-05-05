#!/usr/bin/env python3

from socket import getaddrinfo
from ipaddress import IPv4Address, AddressValueError
import argparse
import time
import logging

def logGet(logname, logfile):
    logger = logging.getLogger(logname)
    logger.setLevel(logging.DEBUG)
    fileHandler = logging.FileHandler(logfile)
    fileHandler.setLevel(logging.DEBUG)
    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s-%(name)s-%(levelname)s: %(message)s')
    consoleHandler.setFormatter(formatter)
    fileHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)
    logger.addHandler(fileHandler)

    return logger

def parseArgs(logger):

    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--fqdn', required=True, help='FQDN', type=str)
    parser.add_argument('-s', '--sleep', default=15, help='time between DNS queries in seconds (default=15)', type=int)

    args = parser.parse_args()

    logger.debug('Arguments parsed')

    return args

def ipValid(ip_address):

    '''
    Validates IP address. If IP address is valid, it returns the ipadress.IPv4Address object,
    if not valid it returns None
    '''

    try:
        ip_obj = IPv4Address(ip_address)
        return ip_obj

    except AddressValueError:
        pass

def getAddr(fqdn):


    addr_set = set()

    add_res = getaddrinfo(fqdn, 0)

    for item in add_res:
        if ipValid(item[-1][0]):
            addr_set.add(item[-1][0])

    return addr_set


def main():

    try:
        logfile = 'fqdn_ip.log'
        logger = logGet(logname='fqdn_ip', logfile=logfile)
        args = parseArgs(logger)
        output_file = '{}-output.txt'.format(args.fqdn)

        try:
            with open(output_file, 'r') as out_file:
                ip_str = out_file.read()
                ip_set = set(ip_str.split(','))
                logger.debug('IP addresses from {}: {}'.format(output_file, ip_set))
        except:
            ip_set = set()

        while True:
            curr_ip_set = getAddr(args.fqdn)
            logger.info('DNS query response: {}'.format(curr_ip_set))
            for ip in curr_ip_set:
                if ip not in ip_set:
                    logger.info('New IP address found: {}'.format(ip))
            ip_set.update(curr_ip_set)
            with open(output_file, 'w') as out_file:
                out_file.write(','.join(ip_set))
            logger.info('{} IP addresses so far for {}: {}'.format(len(ip_set), args.fqdn, ip_set))
            logger.info('Next query in {} seconds'.format(args.sleep))
            time.sleep(args.sleep)
    except KeyboardInterrupt:
        print(ip_set)
        exit()



if __name__ == '__main__':
    main()
