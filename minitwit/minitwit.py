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
# No longer needed to have unique settings after Session DB reconfig
#app.config.from_envvar('MINITWIT_SETTINGS', silent=True)
# Session DB config..
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/minitwit.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'True'
session_app = Session(app)
api_basic_auth = ApiBasicAuth(app)

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db


@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


def init_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    # Added for Session DB
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
    db = get_db()
    with app.open_resource('population.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


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


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'https://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
           (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)


'''
--------------------------
| BEGIN Query Definitions
| - We define a set of queries to be used by both our HTML and JSON responses
--------------------------
'''


def query_home_timeline(user_id):
    return query_db('''
            select message.*, user.* from message, user
            where message.author_id = user.user_id and (
                user.user_id = ? or
                user.user_id in (select whom_id from follower where who_id = ?))
            order by message.pub_date desc limit ?''',
                    [user_id, user_id, PER_PAGE])


def query_public_timeline():
    return query_db('''
          select message.*, user.* from message, user
          where message.author_id = user.user_id
          order by message.pub_date desc limit ?''', [PER_PAGE])


def query_profile_user(username):
    return query_db('select * from user where username = ?',
                    [username], one=True)


def query_followed(user_id, profile_username):
    return query_db('''select 1 from follower where
                follower.who_id = ? and follower.whom_id = ?''',
                    [user_id, profile_username],
                    one=True) is not None


def query_messages(user_id):
    return query_db('''
                select message.*, user.* from message, user where
                user.user_id = message.author_id and user.user_id = ?
                order by message.pub_date desc limit ?''',
                    [user_id, PER_PAGE])


def query_follow_user(user_id, whom_id):
    db = get_db()
    db.execute('INSERT INTO follower (who_id, whom_id) VALUES (?, ?)',
               [user_id, whom_id])
    db.commit()


def query_unfollow_user(user_id, whom_id):
    db = get_db()
    db.execute('DELETE FROM follower WHERE who_id=? AND whom_id=?',
               [user_id, whom_id])
    db.commit()


def query_add_message(user_id, message_text):
    db = get_db()
    db.execute('''INSERT INTO message (author_id, text, pub_date)
          VALUES (?, ?, ?)''', (user_id, message_text,
                                int(time.time())))
    db.commit()


def query_login(username):
    return query_db('''select * from user where
            username = ?''', [username], one=True)


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
    messages = query_home_timeline(session['user_id'])
    my_values = []
    for message in messages:
        my_values.append(
            {'username': message[5], 'email': message[6], 'text': message[2], 'datetime': format_datetime(message[3])})
    return Response(json.dumps(my_values), 200, mimetype='application/json');


# show the public timeline for everyone
@app.route('/api/statuses/public_timeline', methods=['GET', 'DELETE'])
def api_public_timeline():
    messages = query_public_timeline()
    my_values = []
    for message in messages:
        my_values.append(
            {'username': message[5], 'email': message[6], 'text': message[2], 'datetime': format_datetime(message[3])})
    return Response(json.dumps(my_values), 200, mimetype='application/json');


# show messages posted by username
# TODO: currently not doing anything with 'profile_user' or 'followed' here. Could consider adding to JSON response?
@app.route('/api/statuses/user_timeline/<username>', methods=['GET'])
def api_user_timeline(username):  # query_profile_user, query_followed, query_messages
    profile_user = query_profile_user(username)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_followed(session['user_id'], profile_user['user_id'])
    messages = query_messages(profile_user['user_id'])
    my_values = []
    for message in messages:
        my_values.append(
            {'username': message[5], 'email': message[6], 'text': message[2], 'datetime': format_datetime(message[3])})
    return Response(json.dumps(my_values), 200, mimetype='application/json');


# add the authenticated user to the followers of the specified user
@app.route('/api/friendships/create', methods=['POST'])
def api_follow_user():
    if not g.user:
        abort(401)
    username = request.get_json()[0]["username"]
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    query_follow_user(session['user_id'], whom_id)
    return Response(json.dumps({'status': 'successfulFollow', 'whom': username}), 200, mimetype='application/json')


# remove the authenticated user from the followers of username
@app.route('/api/friendships/<username>', methods=['DELETE'])
def api_unfollow_user(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    query_unfollow_user(session['user_id'], whom_id)
    return Response(json.dumps({'status': 'successfulUnfollow', 'whom': username}), 200, mimetype='application/json')


# post a new message from the authenticated user
@app.route('/api/statuses/update', methods=['POST'])
def api_add_message():
    if 'user_id' not in session:
        abort(401)
    message_text = request.get_json()[0]["message"]
    if message_text:
        query_add_message(session['user_id'], message_text)
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
        # elif not check_password_hash(user['pw_hash'], my_args["password"]):
        elif not api_basic_auth.check_credentials(my_args["username"], my_args["password"]):
            error = 'Invalid password'
        else:
            session['user_id'] = user['user_id']
            return Response(json.dumps({'username': my_args['username'], 'status': 'loginSuccessful'}), 200,
                            mimetype='application/json')
    return Response(json.dumps({'status': 'loginFailure', 'error': error}), 401, mimetype='application/json')


# log out the specified user
@app.route('/api/account/verify_credentials', methods=['DELETE'])
def api_logout():
    session.pop('user_id', None)
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
    return render_template('timeline.html', messages=query_home_timeline(session['user_id']))


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    messages = query_public_timeline()
    return render_template('timeline.html', messages=query_public_timeline())


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_followed(session['user_id'], profile_user['user_id'])
    return render_template('timeline.html', messages=query_messages(profile_user['user_id']), followed=followed,
                           profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    query_follow_user(session['user_id'], whom_id)
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
    query_unfollow_user(session['user_id'], whom_id)
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        query_add_message(session['user_id'], request.form['text'])
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
            session['user_id'] = user['user_id']
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
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''INSERT INTO user (
              username, email, pw_hash) VALUES (?, ?, ?)''',
                       [request.form['username'], request.form['email'],
                        generate_password_hash(request.form['password'])])
            db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url