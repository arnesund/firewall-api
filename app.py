#!/usr/bin/env python
from flask import Flask, request, render_template, jsonify, make_response
app = Flask(__name__)


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

@app.route('/api/v1/destinations/<dstip>?srcip=<srcip>')
def post_path(srcip, dstip)
    res = find_path(graph, '157.249.20.0/24', '157.249.32.0/24')
    fw_path = []
    for i in res:
        if "fw" in i or "fg" in i:
            fw_path.append(i)
    result = [fw_path[::2]]
    return jsonify(result)


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
