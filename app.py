from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO
from bson.json_util import dumps, loads
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
jwt = JWTManager(app)
CORS(app)
sIO = SocketIO(app, cors_allowed_origins="*")

app.config['MONGO_URI'] = "mongodb+srv://Admin:Password@cluster0.qoxpoxe.mongodb.net/HackTXDB"
app.config['JWT_SECRET_KEY'] = 'rCzYNeGQ1t'
mongo = PyMongo(app)

#Create post (userid, title, author, content, date)
#Reply to post (text, userid, recipientUserId)
#Relationship (bondscore 0-100, uid1, uid2)
#User (username, password, userid)

@app.route('/')
def mainRoute():
    return jsonify({'Message': "Hello"})

@app.route('/register', methods=['POST'])
def register():
    message = request.json
    username = message['username']
    email = message['email']
    password = message['password']
    saveUser(username, email, password)
    return jsonify({'message': 'Registration successful'})

@app.route('/login', methods=['POST'])
def login():
    message = request.json
    username = message['username']
    password = message['password']

    user = mongo.db.People.find_one({'_id': username})
    if user and check_password_hash(user['password'], password):
        accessToken = create_access_token(identity=username)
        return jsonify({'accessToken': accessToken})
    return jsonify({'message': "authentication failed"}), 401

#Creates a post with uid, title, username, author, content, and date 
@app.route('/createPost', methods=['POST'])
def index():
    message = request.json
    dbPost = {
        "user": message['username'],
        "title": message['title'],
        "content": message['content'],
        "date": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    mongo.db.posts.insert_one(dbPost)
    return jsonify({'message': "Post successful!"})

@app.route('/getPosts', methods=['GET'])
def getPost():
    posts = mongo.db.posts.find().sort("data", -1)
    return dumps(posts)

@app.route('/getUserChats', methods=['POST'])
def getUserChats():
    message = request.json
    user = message['username']
    query = {
        '$or': [
            {'userid1': user},
            {'userid2': user},
        ]
    }
    results = list(mongo.db.user_chats.find(query))
    selectedResults = []
    for result in results:
        if user == result['userid1']:
            selectedResult = {
                'username': result['userid2'],
                'message': result['message'],
            }
            selectedResults.append(selectedResult)
        else:
            selectedResult = {
                'username': result['userid1'],
                'message': result['message'],
            }
            selectedResults.append(selectedResult)
    return jsonify(selectedResults)

#Sends a messsage to recipient uid from sender uid
@app.route('/sendMessage', methods=['POST'])
def sendMessage():
    message = request.json
    dbMessage = {
        "sender_id": message["sender_id"],
        "recipient_id": message["recipient_id"],
        "text": message["message"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    mongo.db.chat_history.insert_one(dbMessage)
    updateUserChats(message["sender_id"], message["recipient_id"], message["message"])
    query = {
        '$or' : [
            {'sender_id': message["sender_id"], 'recipient_id': message["recipient_id"]},
            {'sender_id': message["recipient_id"], 'recipient_id': message["sender_id"]},
        ]
    }
    results = list(mongo.db.chat_history.find(query))
    selectedResults = []
    for result in results:
        selectedResult = {
            'id': str(result['_id']),
            'sender_id': result['sender_id'],
            'recipient_id': result['recipient_id'],
            'text': result['text'],
            'timestamp': result['timestamp'],
        }
        selectedResults.append(selectedResult)
    return jsonify(selectedResults)

#Calculating the bond score between two uid
#1 pt for every message sent (up to 100)
@app.route('/getBondScore', methods=['POST'])
def bondScore():
    message = request.json
    query = {
        '$or' : [
            {'sender_id': message["user"],},
            {'recipient_id': message["user"]},
        ]
    }
    document_count = mongo.db.chat_history.count_documents(query)
    return jsonify({'bondScore': document_count})

    

def saveUser(username, email, password):
    pEncrypt = generate_password_hash(password)
    mongo.db.People.insert_one({'_id': username, 'email': email, 'password': pEncrypt})

def updateUserChats(user1, user2, message):
    testQuery = mongo.db.user_chats.find_one({'$or': [
            {'userid1': user1, 'userid2': user2},
            {'userid1': user2, 'userid2': user1},
        ]})
    
    if testQuery:
        mongo.db.user_chats.update_one(
            {'_id': testQuery['_id']},
            {'$set': {'message': message}}
        )
    else:
        new_chat = {
            'userid1': user1,
            'userid2': user2,
            'message': message
        }
        mongo.db.user_chats.insert_one(new_chat)

@sIO.on('connect')
def handleConnect():
    print("Client successfully connected")

@sIO.on('send_message')
def send_message(message):
    print(f"Recived message: {message}")
    dbMessage = {
        "sender_id": message["sender_id"],
        "recipient_id": message["recipient_id"],
        "text": message["message"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    mongo.db.chat_history.insert_one(dbMessage)
    updateUserChats(message["sender_id"], message["recipient_id"], message["message"])
    sIO.emit('receive_message', message, broadcast=True)

@app.route('/getUserMessages', methods=['POST'])
def getUserMessages():
    message = request.json
    senderId = message['sender_id']
    recipientId = message['recipient_id']
    query = {
        '$or' : [
            {'sender_id': senderId, 'recipient_id': recipientId},
            {'sender_id': recipientId, 'recipient_id': senderId},
        ]
    }
    results = list(mongo.db.chat_history.find(query))
    selectedResults = []
    for result in results:
        selectedResult = {
            'id': str(result['_id']),
            'sender_id': result['sender_id'],
            'recipient_id': result['recipient_id'],
            'text': result['text'],
            'timestamp': result['timestamp'],
        }
        selectedResults.append(selectedResult)
    return jsonify(selectedResults)

if __name__ == '__main__':
    sIO.run(app)