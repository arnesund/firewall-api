#!/usr/bin/env python
from flask import Flask, request, render_template, jsonify, make_response
app = Flask(__name__)

@app.route('/')
def index_page():
    return '''<p>Here's a list of available resources:</p>
    <ul>
    <li>/api/v1/hello</li>
    <li>/user/&lt;username&gt;</li>
    <li>/post/&lt;int:post_id&gt;</li>
    </ul>
    '''

@app.route('/api/v1/hello')
def hello_world():
    return jsonify({'data': 'Hello World!'})

@app.route('/user/<username>')
def show_user_profile(username):
    app.logger.info('Generating template for user {}'.format(username))
    # show the user profile for that user
    return render_template('hello.html', name=username)

@app.route('/post/<int:post_id>')
def show_post(post_id):
    # show the post with the given id, the id is an integer
    return 'Post %d' % post_id

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0')
