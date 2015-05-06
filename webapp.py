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
sys.path.append('../firewall-api-config')


# Load accesslist-database
try:
    db = shelve.open('input/accesslists.db')
    accesslists = db['accesslists']
    firewalls = db['firewalls']
    db.close()
except:
    app.logger.error('Unable to open accesslist-database, exiting!')


# Dictionary with info about any invalid input fields
invalid = {}


#### HTML Endpoints ####

# View main page
@app.route('/')
def index_page():
    return render_template('webapp.html', proto='tcp', invalid=invalid)


# View result page
@app.route('/result')
# /result?srcip=<srcip>&dstip=<dstip>&proto=<proto>&dstport=<dstport>
def result_page():
    # Get access to request arguments
    srcip = request.args.get('srcip')
    dstip = request.args.get('dstip')
    proto = request.args.get('proto')
    dstport = request.args.get('dstport')

    # Validate input data
    invalid = {}
    for field in ['srcip', 'dstip', 'proto', 'dstport']:
        invalid[field] = False

    try:
        IP(srcip)
    except ValueError:
        # Invalid IP address format
        invalid['srcip'] = True

    try:
        IP(dstip)
    except ValueError:
        # Invalid IP address format
        invalid['dstip'] = True

    if proto not in ['tcp', 'udp']:
        invalid['proto'] = True

    try:
        int(dstport)
    except ValueError:
        invalid['dstport'] = True

    # Return index page again if any field contained invalid data
    for field in ['srcip', 'dstip', 'proto', 'dstport']:
        if invalid[field]:
            return render_template('webapp.html', invalid=invalid, srcip=srcip, dstip=dstip, proto=proto, dstport=dstport)


    # Query API for path from source to destination
    get_url = 'http://api.firewall.met.no/api/v1/destinations/{0}?srcip={1}'.format(dstip, srcip)
    path_output = requests.get(get_url)
    get_result = path_output.json()
    calls = []
    for parts in get_result['path']:
        # For each hop, check if firewall would allow the traffic
        get_url = "http://api.firewall.met.no/api/v1/firewalls/{0}/rules/{1}?srcip={2}&dstip={3}&proto={4}&dstport={5}".format(parts[0], parts[1], srcip, dstip, proto, dstport)
        call_query = requests.get(get_url)
        call_result = call_query.json()
        calls.append(call_result)

    # Loop through results to determine if traffic is permitted all the way
    permitted = True
    for entry in calls:
        if not entry['result']['permitted']:
            permitted = False

    # Return HTML template
    return render_template('webapp.html', data=calls, invalid=invalid, permit=permitted, srcip=srcip, dstip=dstip, proto=proto, dstport=dstport)


# Start integrated development webserver
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=80)

