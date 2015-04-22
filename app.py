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

    return render_template('result.html', option1=..., option2=...)



#### API Endpoints ####

# API path endpoint
@app.route('/api/v1/destinations/<dstip>?srcip=<srcip>')
def find_path():
    result = []
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
