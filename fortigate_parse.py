#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Preprosess Cisco firewall config to extract access-list rules
#
import os
import re
import sys
import shelve
import logging
import optparse
from IPy import IP
from datetime import datetime
from ciscoconfparse import CiscoConfParse

CONFIGFILE = 'config.py'


# Load config file
try:
    config = {}
    execfile(CONFIGFILE, config)
except:
    sys.stderr.write('Unable to load config file ({0})! Aborting.\n'.format(CONFIGFILE))
    sys.exit(1)

def main(configfile, verbose):
    # Initialize data structures
    networkgroups = {}
    servicegroups = {}
    hostname = ''

    # Open config files and pre-initialized data structures
    shelvefile = config['NAME_NUMBER_MAPPING']
    try:
        # Name-number mappings
        db = shelve.open(shelvefile)
        name2num = db['cisco_port_name_to_number']
        num2name = db['cisco_port_number_to_name']
        icmptype2num = db['icmp_type_name_to_number']
        db.close()
    except KeyError as e:
        logging.error('Unable to find database entry {0} in shelve file {1}'.format(e, shelvefile))
        sys.exit(1)
    
    # Check that path to accesslist database exists, try to create it if not
    shelvefile = config['ACCESSLIST_DATABASE']
    if not os.path.isfile(shelvefile):
        if not os.path.dirname(shelvefile) == '' and not os.path.isdir(os.path.dirname(shelvefile)):
            try:
                os.makedirs(os.path.dirname(shelvefile))
            except OSError as e:
                logging.error('Path to accesslist DB file "{0}" does not exists, '.format(shelvefile) + \
                    'and I\'m unable to create it. Aborting.')
                sys.exit(1)
    try:
        db = shelve.open(shelvefile)
    except:
        logging.error('Unable to open or create access-list database "{0}"'.format(shelvefile))
        sys.exit(1)

    try:
        # Firewall metadata
        if 'firewalls' in db:
            firewalls = db['firewalls']
        else:
            firewalls = {}
        db.close()
    except KeyError as e:
        logging.error('Unable to find database entry {0} in shelve file {1}'.format(e, shelvefile))
        sys.exit(1)

        
    # Get timestamp as last modification time of config file
    try:
        statinfo = os.stat(configfile)
        timestamp = statinfo.st_mtime
    except Exception as e:
        logging.exception('Unable to get file modification time of config file. Reason: {0}'.format(e))
        sys.exit(1)
    
    # Policy storage
    policy = {}


    # Parse config file to extract all access-lists
    # Track state and current element ID
    index = False
    in_policy = False  
    maps = {}  
    object_name = ""
    for line in open(configfile, 'r').readlines():
        line = line.strip()
        if line == 'config firewall address':
            in_policy = True
        if in_policy and line == 'end':
            in_policy = False
        if not in_policy:
            # Skip line
            continue
        
        if line[:4] == 'edit':
            match = re.search(r'edit \"([^\"]*)\"', line)
            if match:
                index = str(match.groups()[0])
                policy[index] = {}
                #print index
                
        
        elif line == 'next':
            index = False
        
        elif line[:3] == 'set' and index:
            for title in ['subnet']:
                if line.split()[1] == title:
                    contents = ' '.join(line.split()[2:])
                    contents = contents.replace('"', '')
                    #print contents
                    policy[index] = contents
                    
                    break

        
    print policy

if __name__ == '__main__':
    prog = os.path.basename(sys.argv[0])
    usage = """%prog [-h] [-v] [-v] -f <firewall config file>"""
    description = """%prog processes a Cisco firewall config file to extract access-lists, object groups and other relevant info used by the RulesetAnalysis Hadoop jobs."""
    epilog = "2013 - Arne Sund"
    version = "%prog 1.0"

    p = optparse.OptionParser(usage=usage, version=version, description=description, epilog=epilog)
    p.add_option('-v', "--verbose", dest='verbose', action='count', default=0, help='turn on verbose output, apply twice for debug')
    p.add_option('-f', help="Cisco firewall config file", metavar="FILE")
    o, args = p.parse_args()

    # Determine log level from verbose flag
    if o.verbose > 1:
        # Debug logging
        logging.BASIC_FORMAT = "%(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.BASIC_FORMAT = "%(levelname)s - %(message)s"
        if o.verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

    # File argument is mandatory
    if not o.f:
        p.print_usage()
        sys.exit(1)

    accesslists = main(o.f, o.verbose)