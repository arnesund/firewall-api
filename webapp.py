#!/usr/bin/env python
import sys
import shelve
import requests
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
    get_url = 'http://localhost:5000/api/v1/destinations/{0}?srcip={1}'.format(dstip, srcip)
    path_output = requests.get(get_url)
    get_result = path_output.json()
    calls = []
    for parts in get_result['path']:
        calls = "http://localhost:5000/api/v1/firewalls/{0}/rules/{1}?srcip={2}&dstip={3}&proto={4}&dstport={5}".format(parts[0], parts[1], srcip, dstip, proto, dstport)
        call_query = requests.get(calls)
        call_result = call_query.json()
        print call_result
    path = "test string"
    return render_template('result.html', data=path)

# Error handler
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


# Start integrated development webserver
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=80)

