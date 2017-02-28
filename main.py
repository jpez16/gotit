# IMPORTS --------------------------------------------------------------------------------------------------------------
import logging
import os
import bcrypt
import json

from flask import Flask, request, Response
from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4
from functools import wraps

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# SETUP ----------------------------------------------------------------------------------------------------------------

app = Flask(__name__)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    global_limits=["200 per day", "25 per hour"]# global rate limit of 200 per day, and 25 per hour to all routes
)

# DATABASE STUFF -------------------------------------------------------------------------------------------------------

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# helper function just to be safe in case commit() fails
def commit_db():
    try:
        db.session.commit()
    except Exception as e:
        logging.exception(e)
        db.session.rollback()
        db.session.flush()  # reset non-commited.add()


# AUTH STUFF -----------------------------------------------------------------------------------------------------------


def check_auth(token):
    return User.query.filter(User.token == token).count()  # if there doesnt exist an entry then not logged in


def authenticate():
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.args.get('token')
        if not auth or not check_auth(auth):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


# MODELS ---------------------------------------------------------------------------------------------------------------


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.String(100), primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    token = db.Column(db.String(100))
    readingLists = db.relationship('ReadingList', backref='user', lazy='dynamic')

    def __init__(self, **kwargs):
        self.id = str(uuid4())
        self.email = kwargs['email']
        self.password = kwargs['password']
        self.token = kwargs['token']
        self.readingLists = []

    @classmethod
    def get_by_id(cls, _id):
        return cls.query.filter(cls.id == _id).first()

    @classmethod
    def get_by_email(cls, email):
        return cls.query.filter(cls.email == email).first()

    @classmethod
    def get_by_token(cls, token):
        return cls.query.filter(cls.token == token).first()


class ReadingList(db.Model):
    __tablename__ = "readinglist"
    id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(100), db.ForeignKey('user.id'))
    private = db.Column(db.Integer)
    books = db.relationship('Book', backref='readinglist', lazy='dynamic')

    def __init__(self, **kwargs):
        self.id = str(uuid4())
        self.private = kwargs['private']
        self.books = []

    @classmethod
    def get_by_id(cls, _id):
        return cls.query.filter(cls.id == _id).first()


class Book(db.Model):
    __tablename__ = "book"
    isbn = db.Column(db.BigInteger, primary_key=True)
    rl_id = db.Column(db.String(100), db.ForeignKey('readinglist.id'))
    title = db.Column(db.String(160))
    author = db.Column(db.String(80))
    category = db.Column(db.String(80))
    cover_url = db.Column(db.String(240))
    summary = db.Column(db.String(140))

    def __init__(self, **kwargs):
        self.isbn = kwargs['isbn']
        self.title = kwargs['title']
        self.author = kwargs['author']
        self.category = kwargs['category']
        self.cover_url = kwargs['cover_url']
        self.summary = kwargs['summary']

    def to_json(self):
        return {
            "isbn": self.isbn,
            "title": self.title,
            "author": self.author,
            "category": self.category,
            "cover_url": self.cover_url,
            "summary": self.summary
        }

    @classmethod
    def get_by_isbn(cls, isbn):
        return cls.query.filter(cls.isbn == isbn).first()

# ROUTES ---------------------------------------------------------------------------------------------------------------

    @app.route('/create-account', methods=['POST'])
    def create_account_email():
        data = json.loads(request.data.decode('utf-8'))
        if User.get_by_email(data['email']):
            return "Email already in use", 400
        data['password'] = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        # design decision to have user auto logged on account creation
        data['token'] = str(uuid4())
        user = User(**data)
        db.session.add(user)
        commit_db()
        return Response(response=json.dumps({'token': str(user.token)}), status=200)

    @app.route('/login', methods=['POST'])
    def login():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_email(data['email'])
        if not user:
            return "User not found", 404
        if user.token:
            return "Already logged in", 400
        if bcrypt.hashpw(data['password'].encode('utf-8'), user.password.encode('utf-8')) == user.password:
            user.token = str(uuid4())
            commit_db()
            return Response(response=json.dumps({'token': str(user.token)}), status=200)
        return 'Bad password', 401

    @app.route('/logout', methods=['GET'])
    @requires_auth
    def logout():
        user = User.get_by_token(request.args.get('token'))
        # previously generated token is now no longer valid
        user.token = None
        commit_db()
        return "Logged out", 200

    @app.route('/book/read', methods=['POST'])
    def read_book():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_token(request.args.get('token'))
        book = Book.get_by_isbn(data['isbn'])
        rl = ReadingList.get_by_id(book.rl_id)
        if user:
            if rl not in user.readingLists and rl.private:
                return "Access Denied", 401
        else:
            if rl.private:
                return "Access Denied", 401
        return Response(response=json.dumps(book.to_json()), status=200)

    @app.route('/reading-list/create', methods=['POST'])
    @requires_auth
    def create_reading_list():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_token(request.args.get('token'))
        rl = ReadingList(**data)
        user.readingLists.append(rl)
        db.session.add(rl)
        commit_db()
        return Response(response=json.dumps({'rl_id': rl.id}), status=200)

    @app.route('/reading-list/view', methods=['POST'])
    def view_reading_list():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_token(request.args.get('token'))
        rl = ReadingList.get_by_id(data['id'])
        if not rl:
            return "Not found", 404
        if user:
            if rl not in user.readingLists and rl.private:
                return "Access Denied", 401
        else:
            if rl.private:
                return "Access Denied", 401
        books = [x.isbn for x in rl.books]
        return Response(response=json.dumps({'book_isbn_list': books}), status=200)

    @app.route('/reading-list/update', methods=['POST'])
    @requires_auth
    def update_reading_list():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_token(request.args.get('token'))
        rl = ReadingList.get_by_id(data['id'])
        if rl not in user.readingLists:
            return "Reading list not found", 404
        rl = ReadingList.get_by_id(data['id'])
        rl.private = data['private']
        commit_db()
        return Response(response=json.dumps({'id': rl.id}), status=200)

    @app.route('/reading-list/add-book', methods=['POST'])
    @requires_auth
    def add_book_to_reading_list():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_token(request.args.get('token'))
        book = Book.get_by_isbn(data['isbn'])
        if book:
            return "Book already exists", 400

        rl = ReadingList.get_by_id(data['id'])
        if rl not in user.readingLists:
            return "Reading list not found", 404
        rl = ReadingList.get_by_id(data['id'])
        book = Book(**data)
        rl.books.append(book)
        commit_db()
        return Response(response=json.dumps({'isbn': book.isbn}), status=200)

    @app.route('/reading-list/remove-book', methods=['POST'])
    @requires_auth
    def remove_book_from_reading_list():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_token(request.args.get('token'))
        book = Book.get_by_isbn(data['isbn'])
        if not book:
            return "Book not found", 404
        rl = ReadingList.get_by_id(data['id'])
        if rl not in user.readingLists:
            return "Reading list not found", 404
        rl = ReadingList.get_by_id(data['id'])
        rl.books.remove(book)
        db.session.delete(book)
        commit_db()
        return "Book removed from reading list", 200

    @app.route('/reading-list/delete', methods=['POST'])
    @requires_auth
    def delete_reading_list():
        data = json.loads(request.data.decode('utf-8'))
        user = User.get_by_token(request.args.get('token'))
        rl = ReadingList.get_by_id(data['id'])
        if rl not in user.readingLists:
            return "Readling list not found", 404
        rl = ReadingList.get_by_id(data['id'])
        db.session.delete(rl)
        commit_db()
        return "Reading List deleted", 200


# MAIN -----------------------------------------------------------------------------------------------------------------


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
