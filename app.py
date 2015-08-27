#!/usr/bin/env python
import sys
import shelve
from IPy import IP
from firewallrule import FirewallRule
from flask import Flask, request, render_template, jsonify, make_response

# Initialize Flask application
app = Flask(__name__)

# Load config files outside repository
sys.path.append('../firewall-api-config')
from subnets import subnets
from graph import graph


# Load accesslist-database
try:
    db = shelve.open('input/accesslists.db')
    accesslists = db['accesslists']
    firewalls = db['firewalls']
    db.close()
except:
    app.logger.error('Unable to open accesslist-database, exiting!')


#### HTML Endpoints ####

# View main page with API Documentation
@app.route('/')
def index_page():
    return render_template('apidocs.html')


#### API Endpoints ####

def find_path(graph, start, end, path=[]):
    path = path + [start]
    if start == end:
        return path
    if not graph.has_key(start):
        return None
    for node in graph[start]:
        if node not in path:
            newpath = find_path(graph, node, end, path)
            if newpath: return newpath
    return None

def get_subnet(ip):
    address = IP(ip)
    for subnet in subnets:
        if address in subnet:
            return str(subnet)


@app.route('/api/v1/destinations')
def list_destinations():
    '''Return a list of all destination subnets known to the API'''
    res = []
    for subnet in subnets:
        res.append(str(subnet))

    return jsonify({'destinations': res})


# API path endpoint
@app.route('/api/v1/destinations/<dstip>')
def post_path(dstip, srcip=None):
    if not srcip:
        srcip = request.args.get('srcip')

    # Determine subnet that srcip and dstip belong to
    src_subnet = get_subnet(srcip)
    dst_subnet = get_subnet(dstip)

    # Determine path
    res = find_path(graph, src_subnet, dst_subnet)

    # Filter out every object that is not a firewall
    fw_path = []
    if res:
        for i in res:
            if "fw" in i or "fg" in i:
                fw_path.append(i)
    else:
        return jsonify({'error': 'Unable to determine path from {0} to {1}'.format(srcip, dstip)}), 404

    # Parse out every other access list
    result = fw_path[::2]

    # Postprocess result list and return results
    post_result = []
    for entry in result:
        parts  = entry.split("_")
        post_result.append(parts)
    return jsonify({'path': post_result})




@app.route('/api/v1/firewalls/<hostname>/rules/<acl>')
def get_firewall_rules(hostname, acl, srcip=None, dstip=None, proto=None, dstport=None, ruleobjects=False):
    if not srcip:
        srcip = request.args.get('srcip')
    if not dstip:
        dstip = request.args.get('dstip')
    if not proto:
        proto = request.args.get('proto')
    if not dstport:
        dstport = request.args.get('dstport')
    if not ruleobjects:
        ruleobjects = request.args.get('ruleobjects')

    # Validate existence of accesslist data
    if hostname not in firewalls or hostname not in accesslists:
        return jsonify({'error': 'Firewall not found in database, please try again.'}), 404
    if acl not in accesslists[hostname]:
        return jsonify({'error': 'Accesslist not found in database, please try again.'}), 404

    # Use case 1: Check if specific traffic is permitted or denied
    if srcip and dstip and proto and dstport:
        # Create Connection object to match against firewall rules
        conn = FirewallRule(True, proto, '', srcip, dstip, dport=dstport)

        # Create list of rule IDs to check (only those with the same protocol, or protocol=IP)
        if proto in accesslists[hostname][acl]['protocols']:
            relevantrules = accesslists[hostname][acl]['protocols'][proto] + \
                            accesslists[hostname][acl]['protocols']['ip']
        else:
            relevantrules = accesslists[hostname][acl]['protocols']['ip']
        relevantrules.sort()

        for ruleindex in relevantrules:
            rule = accesslists[hostname][acl]['rules'][ruleindex]

            # Special case: If rule is a Deny rule, connection object parameter 'action' must be altered temporarily
            if rule.action == False:
                conn.action = False

            # Check if connection would be permitted by this rule
            if conn in rule:
                result = {'permitted': rule.action, 'firewallrule': str(rule), 'rulecomment': '\n'.join(rule.comments)}
                break

            # Reset back to default
            conn.action = True
        else:
            # No matching rules found, so the traffic hits the implicit deny at end of ACL
            result = {'permitted': False}

    # Use case 2: Return entire ACLs or relevant parts of them
    else:
        # Return an ordered list of firewall rules in ACL
        result = {'rules': []}
        for rule in accesslists[hostname][acl]['rules']:
            # Filter if some of the parameters where supplied
            if srcip and srcip not in rule.src:
                continue
            if dstip and dstip not in rule.dst:
                continue
            if rule.protocol != 'ip':
                if proto and rule.protocol != proto:
                    continue
            if rule.dport != [-1]:
                if dstport and dstport not in rule.dport:
                    continue
            
            # Add rule object to result dict
            if ruleobjects:
                # Append complete rule object as a dictionary
                result['rules'].append({'action': rule.action,
                    'protocol': rule.protocol,
                    'src': str(rule.src),
                    'dst': str(rule.dst),
                    'sport': rule.sport,
                    'dport': rule.dport,
                    'logging': rule.logging,
                    'original': rule.original,
                    'comments': rule.comments,
                    'ruleindex': rule.ruleindex,
                    'rulenum': rule.rulenum})
            else:
                # Append simplified string representation of rule
                result['rules'].append(str(rule))

    # Add info from request for easier reference
    result['firewall'] = hostname
    result['accesslist'] = acl

    return jsonify({'result': result})



# API test endpoint
@app.route('/api/v1/hello')
def hello_world():
    return jsonify({'data': 'Hello World!'})


# Error handler
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


# Start integrated development webserver
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=80)
