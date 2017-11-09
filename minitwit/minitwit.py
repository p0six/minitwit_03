# -*- coding: utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~

    A microblogging application written with Flask and sqlite3.

    :copyright: (c) 2015 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

import time
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
    render_template, abort, g, flash, _app_ctx_stack, json, jsonify, Response
from werkzeug import check_password_hash, generate_password_hash
from flask_sessionstore import Session
from flask_basicauth import BasicAuth
from flask_pymongo import PyMongo


class ApiBasicAuth(BasicAuth):
    def check_credentials(self, username, password):
        user = query_login(username)
        if check_password_hash(user['pw_hash'], password):
            return True
        else:
            return False


# configuration
DATABASE = '/tmp/minitwit.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

# create our little application :)
app = Flask('minitwit')
app.config.from_object(__name__)
## No longer needed to have unique settings after Session DB reconfig
# app.config.from_envvar('MINITWIT_SETTINGS', silent=True)
# Session DB config..
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/minitwit.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'True'
session_app = Session(app)
api_basic_auth = ApiBasicAuth(app)
mongo = PyMongo(app)

def init_db():
    # Added for Session DB
    # We can consider migrating this to MongoDB as well via http://flask.pocoo.org/snippets/110/
    session_app.app.session_interface.db.create_all()


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')


'''
--------------------
| BEGIN populatedb
--------------------
'''


def populate_db():
    """Initializes the database."""
    mongo.db.users.drop()
    mongo.db.messages.drop()

    mongo.db.users.insert({'username':'mike','email':'romerom@gmail.com', 'pw_hash': 'pbkdf2:sha256:50000$7VKjFQZP$da63f8b89e016788e6e58245f242e13d55f73d15b83c47c6af606d92bbe1dd52',
      'followers': ['ninjitsu', 'theromerom', 'julia'], 'following': []})
    mongo.db.users.insert({'username':'ninjitsu','email':'romerom@csu.fullerton.edu','pw_hash': 'pbkdf2:sha256:50000$7VKjFQZP$da63f8b89e016788e6e58245f242e13d55f73d15b83c47c6af606d92bbe1dd52',
      'followers': ['theromerom', 'julia'], 'following': ['mike']})
    mongo.db.users.insert({'username':'theromerom','email':'theromerom@yahoo.com','pw_hash': 'pbkdf2:sha256:50000$7VKjFQZP$da63f8b89e016788e6e58245f242e13d55f73d15b83c47c6af606d92bbe1dd52',
      'followers':['julia'], 'following':['mike', 'ninjitsu']})
    mongo.db.users.insert({'username':'julia','email':'julia@email.com','pw_hash': 'pbkdf2:sha256:50000$7VKjFQZP$da63f8b89e016788e6e58245f242e13d55f73d15b83c47c6af606d92bbe1dd52',
      'followers':[], 'following': ['mike', 'ninjitsu', 'theromerom']})

    mongo.db.messages.insert({'username': 'mike', 'email': 'romerom@gmail.com', 'text': 'i follow nobody. nerds!', 'pub_date':1505497615})
    mongo.db.messages.insert({'username': 'ninjitsu', 'email': 'romerom@csu.fullerton.edu', 'text': 'i love candy', 'pub_date':1505497635})
    mongo.db.messages.insert({'username': 'mike', 'email': 'romerom@gmail.com', 'text': 'mikes second tweet', 'pub_date': 1505497645})
    mongo.db.messages.insert({'username': 'mike', 'email': 'romerom@gmail.com', 'text': 'mike\'s third tweet!', 'pub_date':1505497655})
    mongo.db.messages.insert({'username': 'ninjitsu', 'email': 'romerom@csu.fullerton.edu','text': 'ninjitsu the ginsu\'s 2nd!', 'pub_date':1505497665})
    mongo.db.messages.insert({'username': 'theromerom', 'email': 'theromerom@yahoo.com', 'text': 'wtf is a romerom numba 1!', 'pub_date':1505497675})
    mongo.db.messages.insert({'username': 'theromerom', 'email': 'theromerom@yahoo.com', 'text': 'romerom like romadon?', 'pub_date':1505497685})
    mongo.db.messages.insert({'username': 'julia', 'email': 'julia@email.com', 'text': 'exeternal from ingress?', 'pub_date':1505497695})
    mongo.db.messages.insert({'username': 'julia', 'email': 'julia@email.com', 'text': 'yes for sure?', 'pub_date':1505497705})


@app.cli.command('populatedb')
def populatedb_command():
    """Populate the database tables."""
    populate_db()
    print('Populated the database.')


'''
--------------------
| END populatedb
--------------------
'''


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = mongo.db.users.find_one({ 'username' : username }, {'_id': 1})
    if rv is not None:
        return rv
    else:
        return None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(float(timestamp)).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'https://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
           (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'username' in session:
        g.user = mongo.db.users.find_one({'username': session['username']})


'''
--------------------------
| BEGIN Query Definitions
| - We define a set of queries to be used by both our HTML and JSON responses
--------------------------
'''


def query_home_timeline(username):
    user_rv = mongo.db.users.find_one({'username': username}, {'_id': 0})
    user_rv['following'].append(user_rv['username'])
    return mongo.db.messages.find({'username': { "$in" : user_rv['following']}}).sort('pub_date', -1)


def query_public_timeline():
    return mongo.db.messages.find({}).sort('pub_date', -1)


def query_profile_user(username):
    return mongo.db.users.find_one({'username': username}, {'followers': 0, 'following': 0})

def query_messages(username):
    return mongo.db.messages.find({'username': username}).sort('pub_date', -1)


def query_followed(username, profile_username):
    if mongo.db.users.find({'username': username, 'following': [ profile_username ]}).count() > 0:
      return True
    else:
      return False


def query_follow_user(username, follower):
    mongo.db.users.update({'username': username}, { "$push": {'following': follower}})


def query_unfollow_user(username, follower):
    mongo.db.users.update({'username': username}, { "$pull": {'following': follower }})


def query_add_message(username, message_text):
    user_rv = mongo.db.users.find_one({'username': username})
    mongo.db.messages.insert({'username': username, 'text': message_text, 'pub_date': float(time.time()), 'email': user_rv['email']})


def query_login(username):
    return mongo.db.users.find_one({'username': username})


'''
------------------------
| END Query Definitions
--------------
------------------
| BEGIN API Functions
| - We define a set of API functions, as specified in our requirements document
------------------
'''


# show the timeline for the authenticated user
@app.route('/api/statuses/home_timeline', methods=['GET'])
def api_home_timeline():
    if not g.user:
        return redirect(url_for('api_public_timeline'))
    messages = query_home_timeline(session['username'])
    my_values = []
    for message in messages:
        my_values.append(
            {'username': message['username'], 'email': message['email'], 'text': message['text'], 'datetime': format_datetime(message['pub_date'])})
    return Response(json.dumps(my_values), 200, mimetype='application/json');


# show the public timeline for everyone
@app.route('/api/statuses/public_timeline', methods=['GET', 'DELETE'])
def api_public_timeline():
    messages = query_public_timeline()
    my_values = []
    for message in messages:
        my_values.append(
            {'username': message['username'], 'email': message['email'], 'text': message['text'], 'datetime': format_datetime(message['pub_date'])})
    return Response(json.dumps(my_values), 200, mimetype='application/json');


# show messages posted by username
@app.route('/api/statuses/user_timeline/<username>', methods=['GET'])
def api_user_timeline(username):  # query_profile_user, query_followed, query_messages
    profile_user = query_profile_user(username)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_followed(session['username'], username)
    messages = query_messages(username)
    my_values = []
    for message in messages:
        my_values.append(
            {'username': message['username'], 'email': message['email'], 'text': message['text'], 'datetime': format_datetime(message['pub_date'])})
    return Response(json.dumps(my_values), 200, mimetype='application/json');


# add the authenticated user to the followers of the specified user
@app.route('/api/friendships/create', methods=['POST'])
def api_follow_user():
    if not g.user:
        abort(401)
    username = request.get_json()[0]["username"]
    whom_id = get_user_id(username) # we want this to remain
    if whom_id is None:
        abort(404)
    query_follow_user(session['username'], username)
    return Response(json.dumps({'status': 'successfulFollow', 'whom': username}), 200, mimetype='application/json')


# remove the authenticated user from the followers of username
@app.route('/api/friendships/<username>', methods=['DELETE'])
def api_unfollow_user(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username) # we want this to remain..
    if whom_id is None:
        abort(404)
    query_unfollow_user(session['username'], username)
    return Response(json.dumps({'status': 'successfulUnfollow', 'whom': username}), 200, mimetype='application/json')


# post a new message from the authenticated user
@app.route('/api/statuses/update', methods=['POST'])
def api_add_message():
    if 'username' not in session:
        abort(401)
    message_text = request.get_json()[0]["message"]
    if message_text:
        query_add_message(session['username'], message_text)
    return Response(json.dumps({'status': 'successfulMessage'}), 200, mimetype='application/json')


# log in the specified user
@app.route('/api/account/verify_credentials', methods=['GET'])
def api_login():
    if g.user:
        return redirect(url_for('api_home_timeline'))
    error = None
    if request.method == 'GET':
        my_args = request.args.to_dict();
        user = query_login(my_args['username'])
        if user is None:
            error = 'Invalid username'
        elif not api_basic_auth.check_credentials(my_args["username"], my_args["password"]):
            error = 'Invalid password'
        else:
            session['username'] = user['username']
            return Response(json.dumps({'username': my_args['username'], 'status': 'loginSuccessful'}), 200,
                            mimetype='application/json')
    return Response(json.dumps({'status': 'loginFailure', 'error': error}), 401, mimetype='application/json')


# log out the specified user
@app.route('/api/account/verify_credentials', methods=['DELETE'])
def api_logout():
    session.pop('username', None)
    return Response(json.dumps({'status': 'logoutSuccessful'}), 200, mimetype='application/json')


'''
------------------------
| END API Functions 
------------------------
'''


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    return render_template('timeline.html', messages=query_home_timeline(session['username']))


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    messages = query_public_timeline()
    return render_template('timeline.html', messages=messages)


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user = query_profile_user(username)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_followed(session['username'], username)
    return render_template('timeline.html', messages=query_messages(username), followed=followed,
                           profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    query_follow_user(session['username'], username)
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    query_unfollow_user(session['username'], username)
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'username' not in session:
        abort(401)
    if request.form['text']:
        query_add_message(session['username'], request.form['text'])
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = query_login(request.form['username'])
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['username'] = user['username']
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                        '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            print "herpy"
            error = 'The username is already taken'
        else:
            mongo.db.users.insert({'username': request.form['username'],'email':
                request.form['email'],'pw_hash': generate_password_hash(request.form['password']),
                                   'followers':[], 'following': []})

            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('username', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url