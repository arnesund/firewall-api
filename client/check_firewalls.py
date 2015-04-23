#!/usr/bin/env python
# coding: utf-8
#
# Check if the firewalls allow a certain type of traffic
#
import sys
import optparse
import requests

# Base URL to API server
APISERVER='http://api.firewall.met.no/api/v1'

# Command line option parsing info
usage = '%prog [-h|--help] [-s|--srcip SOURCE-IP] [-d|--dstip DESTINATION-IP] [--proto PROTOCOL] [-p|--dstport DESTIONATION-PORT]'
description = """Check if the firewalls allow specified traffic"""
epilog = 'Author: Arne Sund'
version = '%prog 1.0'

# Initialize command line parsing
p = optparse.OptionParser(usage=usage, version=version, description=description, epilog=epilog)
p.add_option('-s', "--srcip", dest='srcip', metavar="SOURCE-IP", help='Source IP address (required)')
p.add_option('-d', "--dstip", dest='dstip', metavar="DESTINATION-IP", help='Destination IP address (required)')
p.add_option("--proto", dest='proto', metavar="PROTOCOL", help='Protocol: TCP or UDP (required)')
p.add_option('-p', "--dstport", dest='dstport', metavar="DESTINATION-PORT", help='Destination Port (required)')
options, args = p.parse_args()

# Parse command line options
if not options.srcip:
    print('ERROR: Source IP address not supplied.\n')
    p.print_help()
    sys.exit(1)
else:
    srcip = options.srcip

if not options.dstip:
    print('ERROR: Destination IP address not supplied.\n')
    p.print_help()
    sys.exit(1)
else:
    dstip = options.dstip

if not options.proto:
    print('ERROR: Protocol (TCP/UDP) not supplied.\n')
    p.print_help()
    sys.exit(1)
else:
    proto = options.proto

if not options.dstport:
    print('ERROR: Destination port not supplied.\n')
    p.print_help()
    sys.exit(1)
else:
    dstport = options.dstport

# Query API for path from srcip to dstip
res = requests.get(APISERVER + '/destinations/{0}?srcip={1}'.format(dstip, srcip))

results = []
if res:
    for fw, acl in res.json()['path']:
        # Query API for rules that allow this traffic on this firewall
        chk = requests.get(APISERVER + '/firewalls/{0}/rules/{1}?srcip={2}&dstip={3}&proto={4}&dstport={5}'.format(fw, acl, srcip, dstip, proto, dstport))
        if chk:
            results.append(chk.json())
        else:
            print('ERROR: Unable to check firewall {} and ACL {}...'.format(fw, acl))
else:
    print('ERROR: Unable to get path from {} to {}, please try again.'.format(srcip, dstip))

# Loop through to find aggregated result (ultimately permitted or denied)
permitted = True
for entry in results:
    if not entry['result']['permitted']:
        permitted = False

print('')
if permitted:
    print('Traffic is PERMITTED through the firewalls!')
else:
    print('Traffic is DENIED by at least one of the firewalls!')
print('')

for entry in results:
    data = entry['result']
    if data['permitted']:
        print('PERMITTED:')
        print(' Firewall: ' + data['firewall'])
        print(' Access-list: ' + data['accesslist'])
        for line in data['rulecomment'].split('\n'):
          print(' ' + line)
        print(' ' + data['firewallrule'])
    else:
        print('DENIED:')
        print(' Firewall: ' + data['firewall'])
        print(' Access-list: ' + data['accesslist'])
    print('')

