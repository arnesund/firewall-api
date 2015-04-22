#!/usr/bin/env python
import sys
from flask import Flask, request, render_template, jsonify, make_response
app = Flask(__name__)
from IPy import IP

sys.path.append('../')
from subnets import subnets
from graph import graph


#### HTML Endpoints ####

# View main page
@app.route('/')
def index_page():
    return render_template('index.html')


# View result page
@app.route('/result?srcip=<srcip>&dstip=<dstip>&dstport=<dstport>')
def result_page(srcip, dstip, dstport):
    # Call other functions to perform check
    # find_path(...)
    # ...
    # ...

    return render_template('result.html')



#### API Endpoints ####

# API path endpoint
def find_path(graph, start, end, path=[]):
    app.logger.debug('find_path({},{})'.format(start, end))
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
def post_path(dstip):
    srcip = request.args.get('srcip')
    src_subnet = get_subnet(srcip)
    app.logger.debug(src_subnet)
    dst_subnet = get_subnet(dstip)
    app.logger.debug(dst_subnet)
    res = find_path(graph, src_subnet, dst_subnet)
    app.logger.debug(res)
    fw_path = []
    for i in res:
        if "fw" in i or "fg" in i:
            fw_path.append(i)
    result = fw_path[::2]
    return jsonify({'path': result})


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
