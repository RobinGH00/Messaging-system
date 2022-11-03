from flask import Flask, render_template, flash, redirect, url_for, session, request, abort
from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4
from flask_socketio import SocketIO, emit, Namespace
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import random, string
from sqlalchemy import exists, case, distinct
from flask_moment import Moment
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mY_sEcreT_keY'


database = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
moment = Moment(app)


login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Random string generator for message and thread id
def randomstring(type, pmthread=None):
	letters = string.ascii_lowercase
	randstr =  ''.join(random.choice(letters) for i in range(8))

	if pmthread:
		if not database.session.query(exists().where(Message.thread_id == randstr)).scalar():
			return randstr
		else:
			randomstring(type=Message, pmthread=True)

	if not database.session.query(exists().where(type.url == randstr)).scalar():
		return randstr
	else:
		randomstring(type=type)

#Database models, Users and messages
class User(database.Model, UserMixin):
    __tablename__ = 'users'
    id = database.Column(database.Integer, primary_key=True)
    username = database.Column(database.String(80))
    password = database.Column(database.String(80))
    websocket_id = database.Column(database.String, unique=True, index=True)


class Message(database.Model):
    __tablename__ = 'messages'
    id = database.Column(database.Integer(), primary_key=True)
    url = database.Column(database.String())
    sender_id = database.Column(database.String())
    recipient_id = database.Column(database.String())
    subject = database.Column(database.String())
    body = database.Column(database.String())
    timestamp = database.Column(database.DateTime)
    read = database.Column(database.Boolean(), default=False)
    thread_id = database.Column(database.String())
    sender_del = database.Column(database.Boolean())
    recipient_del = database.Column(database.Boolean())

#App view routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username').lower()
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        flash('Username or Password is inncorect, try again.')
        return redirect(url_for('login'))
    login_user(user)
    return redirect(url_for('messages'))


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username').lower()
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()

    if user:
        flash('Username is taken')
        return redirect(url_for('register'))

    new_user = User(username=username, password=generate_password_hash(password, method='sha256'), websocket_id=uuid4().hex)
    database.session.add(new_user)
    database.session.commit()
    return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/messages/', methods=['POST', 'GET'])
@login_required
def messages():
	#Thread ownership security check
	if request.args.get('thread_id'):
		if not database.session.query(Message).filter(Message.thread_id == request.args.get('thread_id'), Message.recipient_id == current_user.username) \
		or not database.session.query(Message).filter(Message.thread_id == request.args.get('thread_id'), Message.sender_id == current_user.username):
			abort(404)

		#Fetches messages in the thread for the current user
		message_sender = database.session.query(Message).filter(Message.thread_id == request.args.get('thread_id'), Message.sender_id == current_user.username, Message.sender_del == False)
		message_recipient = database.session.query(Message).filter(Message.thread_id == request.args.get('thread_id'), Message.recipient_id == current_user.username, Message.recipient_del == False)
		message_thread = message_sender.union(message_recipient).order_by(Message.timestamp.asc())

		if not message_thread.count():
				abort(404)

		thread_count = len(message_thread.all())
		if thread_count <= 5:
			offset = 0
		else:
			offset = thread_count-5
		message_thread_paginated = message_thread.offset(offset).limit(5)

		if request.args.get('fetch'): 
			fetch_last_query = database.session.query(Message).filter(Message.url == request.args.get('fetch')).one()
			testq = message_sender.union(message_recipient).order_by(Message.timestamp.asc()).filter(Message.message_id < fetch_last_query.id) 
			testq_count = testq.count()
			if testq_count-5 < 0:
				offsetcnt = 0
			else:
				offsetcnt = testq_count-5
			testq = testq.offset(offsetcnt)

			fetched_messages = render_template('new_message.html', message_thread=testq)
			return {'status': 200, 'fetched_messages': fetched_messages, 'offsetcnt':offsetcnt}

		#This marks all messages within thread that are in the current_user's unread as read upon thread open if current user is recipient
		for message in message_thread:
			if current_user.username == message.recipient_id:
				if message.read == False:
					message.read = True
					database.session.commit()

		#Sets the recipient ID on replies so if a user is sending to themself, the recipient ID will be correct. 
		if current_user.username == message_thread[0].sender_id:
			recip = message_thread[0].recipient_id
		else:
			recip = message_thread[0].sender_id

		#Informs socket if messages are all read.
		if not database.session.query(Message).filter(Message.recipient_id == current_user.username, Message.read == False).all():
			socketio.emit(current_user.websocket_id+'_notify', {'type':'mailbox', 'notify':'false'}, namespace='/messages')

		#Informs socket when the thread is read. And possibly update read or unread
		socketio.emit(current_user.websocket_id+'_notify', {'type':'thread', 'notify':'false', 'thread_id':request.args.get('thread_id')}, namespace='/messages')

		return render_template('read_message_thread.html', message_thread=message_thread_paginated, thread_id=request.args.get('thread_id'),\
								recip=recip, thread_count=thread_count)


	else:
		page = request.args.get('page', 1, type=int)

		unread_messages = database.session.query(Message).filter(Message.recipient_id == current_user.username, Message.recipient_del == False).order_by(Message.timestamp.desc())
		#Sorts each message thread according to the datetime of the last recieved message in each thread which is then used in the sorting
		unread_ids = {}

		for message in unread_messages:
			if not unread_ids.get(message.thread_id):
				unread_ids[message.thread_id] = len(unread_ids)+1
		if not unread_ids:
			sort = None
		else:
			sort = case(value=Message.thread_id, whens=unread_ids).asc()

		#Fixes message threads viewed so duplicates will not be displayed
		thread_list = []
		message_thread_list = []
		for message in unread_messages:
			if message.thread_id not in thread_list:
				thread_list.append(message.thread_id)
				message_thread_list.append(message.url)

		message_threads = unread_messages.filter(Message.url.in_(message_thread_list)).order_by(sort)

		#Determines what is highlighted on the private messages screen for unread messages. List is sent to messages.html where Jinja2 logic executes.
		unread_threads = unread_messages.filter(Message.read == False).order_by(Message.timestamp.desc()).all()
		if unread_threads:
			unread_threads_list = []
			for message in unread_threads:
				unread_threads_list.append(message.thread_id)
		else:
			unread_threads_list = []
		message_threads = message_threads.paginate(page, 5, False)

		return render_template('messages.html', messages=message_threads.items, unread_threads_list=unread_threads_list,)



#Database check for sender/recipient del true and return 404 if so.
@app.route('/messages/socket/', methods=['POST', 'GET']) 
@login_required
def message_socket():
	message = database.session.query(Message).filter(Message.url == request.args.get('url')).all()

	if not message:
		abort(404)
	if current_user.username == message[0].recipient_id or current_user.username == message[0].sender_id:
		pass
	else:
		return {'status': 401}
	if current_user.username == message[0].recipient_id and request.args.get('read'):
		message[0].read = True 
		database.session.commit()
		if not database.session.query(Message).filter(Message.recipient_id == current_user.username, Message.read == False, Message.recipient_del == False).all():
			socketio.emit(current_user.websocket_id+'_notify', {'type':'mailbox', 'notify':'false'}, namespace='/messages')
	if request.args.get('read'):
		socketio.emit(current_user.websocket_id+'_notify', {'type':'thread', 'notify':'false', 'thread_id':message[0].thread_id}, namespace='/messages')
		render_message = render_template('new_message.html', message_thread=message)
		return {'status':200, 'message':render_message}
	else:
		render_thread = render_template('new_thread.html', messages=message, unread_threads_list=[message[0].thread_id])
		return {'status':200, 'thread':render_thread, 'thread_id':message[0].thread_id}





@app.route('/messages/new/', methods=['POST', 'GET'])
@login_required
def sendmessage():
	if request.method == 'GET':
		return render_template('send.html')
	if request.method == 'POST':
		#Data security checks
		if request.json.get('body') == '' or request.json.get('body') == None or len(request.json.get('subject')) > 70:
			return {'status':418}
		#Mitigates messaging attacks by ensuring thread_id has not been modified on the end user computer by checking thread ownership
		if request.json.get('thread_id'):
			if database.session.query(Message).filter(Message.thread_id == request.json.get('thread_id'), Message.sender_id == current_user.username).all() or \
				database.session.query(Message).filter(Message.thread_id == request.json.get('thread_id'), Message.recipient_id == current_user.username).all():
				pass
			else:
				return {'status': 418}

		#Checks if the username exists
		if not database.session.query(User).filter(User.username == request.json.get('recipient_id').lower()).first():
			return {'error':'No user exists with that username.'}

		url = randomstring(type=Message)
		timestamp=datetime.utcnow()

		if request.json.get('thread_id'):
			thread_id = request.json.get('thread_id')
			thread_query = database.session.query(Message).filter(Message.thread_id == thread_id)
			subject = thread_query.order_by(Message.timestamp.desc()).first().subject
		else:
			thread_id = randomstring(type=Message, pmthread=True)
			subject = request.json.get('subject')

		newMessage = Message(sender_id=current_user.username, recipient_id=request.json.get('recipient_id').lower(), subject=subject, body=request.json.get('body'), url=url, \
						 thread_id=thread_id, timestamp=timestamp, sender_del=False, recipient_del=False)
		database.session.add(newMessage)
		database.session.commit()

		recipient_websocket_id = database.session.query(User).filter(User.username == request.json.get('recipient_id').lower()).one().websocket_id
		socketio.emit(recipient_websocket_id+'_newmsg', {'message_url' : url}, namespace='/messages') 
		socketio.emit(current_user.websocket_id+'_newmsg', {'message_url' : url}, namespace='/messages') 
		socketio.emit(thread_id, {'message_url' : url}, namespace='/messages')

		return {'status': 200}


if __name__ == "__main__":
    socketio.run(app)
	
	
