#!/usr/bin/env python
import sys
import shelve
from IPy import IP
from firewallrule import FirewallRule
from flask import Flask, request, render_template, jsonify, make_response

# Initialize Flask application
app = Flask(__name__)

# Load config files outside repository
sys.path.append('../')
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

# View main page
@app.route('/')
def index_page():
    return render_template('index.html')


# View result page
@app.route('/result')
# /result?srcip=<srcip>&dstip=<dstip>&proto=<proto>&dstport=<dstport>
def result_page():
    # Get access to request arguments
    srcip = request.args.get('srcip')
    dstip = request.args.get('dstip')
    proto = request.args.get('proto')
    dstport = request.args.get('dstport')

    # Call other functions to perform check
    # find_path(...)
    # ...
    # ...

    path_output = post_path(dstip, srcip)

    path = []
    path.append(json.loads(path_output))

    return render_template('result.html', data=path)


#### API Endpoints ####

# API path endpoint
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

@app.route('/api/v1/destinations/<dstip>')
def post_path(dstip, srcip=None):
    if not srcip:
        srcip = request.args.get('srcip')
    src_subnet = get_subnet(srcip)
    dst_subnet = get_subnet(dstip)
    res = find_path(graph, src_subnet, dst_subnet)
    fw_path = []
    for i in res:
        if "fw" in i or "fg" in i:
            fw_path.append(i)
    result = fw_path[::2]
    post_result = []
    for entry in result:
        parts  = entry.split("_")
        post_result.append(parts)
    return jsonify({'path': post_result})




@app.route('/api/v1/firewalls/<hostname>/rules/<acl>')
def get_firewall_rules(hostname, acl, srcip=None, dstip=None, proto=None, dstport=None):
    if not srcip:
        srcip = request.args.get('srcip')
    if not dstip:
        dstip = request.args.get('dstip')
    if not proto:
        proto = request.args.get('proto')
    if not dstport:
        dstport = request.args.get('dstport')

    # Validate existence of accesslist data
    if hostname not in firewalls or hostname not in accesslists:
        return jsonify({'error': 'Firewall not found in database, please try again.'}), 404
    if acl not in accesslists[hostname]:
        return jsonify({'error': 'Accesslist not found in database, please try again.'}), 404

    # Create Connection object to match against firewall rules
    conn = FirewallRule(True, proto, '', srcip, dstip, dport=dstport)

    # Find rules to check (only those with the same protocol, or protocol=IP)
    relevantrules = accesslists[hostname][acl]['protocols'][proto] + \
                    accesslists[hostname][acl]['protocols']['ip']
    relevantrules.sort()

    for ruleindex in relevantrules:
        # Check if connection would be permitted by this rule
        if conn in accesslists[hostname][acl]['rules'][ruleindex]:
            result = (True, repr(accesslists[hostname][acl]['rules'][ruleindex]))
            break

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
    app.run(host='0.0.0.0')
