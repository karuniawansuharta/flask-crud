from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask (__name__)
app.config['SECRET_KEY'] = 'awan10'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/python'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255))

class Books(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    isbn = db.Column(db.String(50), unique = True)
    title = db.Column(db.String(50))
    publication_date = db.Column(db.String(50))
    edition = db.Column(db.String(50))
    quantity = db.Column(db.String(50))
    price = db.Column(db.String(50))
    author = db.Column(db.String(50))
    publisher = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited_at = db.Column(db.DateTime, default=datetime.utcnow)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({
                'message' : 'Token is missing!'
            }), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                    .first()
        except:
            return jsonify({
                'message' : 'Token is invalid!'
            }), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/user', methods = ['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()

    output = []
    for user in users:
        output.append({
            'public_id' : user.public_id,
            'name' : user.name,
            'email' : user.email
        })
    return jsonify({
        'users' : output
    })

@app.route('/login', methods = ['POST'])
def login():
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(
            'Could not verify 1', 401, {
                'WWW-Authenticate' : 'Basic Ralm = "Login required!"'
            }
        )
    user = User.query\
        .filter_by(email = auth.get('email'))\
        .first()
    
    if not user:
        return make_response(
            'Could not verify 2', 401, {
                'WWW-Authenticate' : 'Basic Ralm = "User does not exist!"'
            }
        )
    if check_password_hash(user.password, auth.get('password')):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 60)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({
            'token' : token.decode('UTF-8')
        })), 201

    return make_response(
        'Could not verify 3', 403, {
            'WWW-Authenticate' : 'Basic realm = "Wrong Password"'
        }
    )

@app.route('/signup', methods = ['POST'])
def signup():
    data = request.form

    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    user = User.query\
        .filter_by(email = email)\
        .first()
    
    if not user:
        user = User(
            public_id = str(uuid.uuid4()),
            name = name,
            email = email,
            password = generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered!.', 201)
    else:
        return make_response('User Already Exist. Plese Login.', 202)

@app.route('/books', methods = ['GET'])
@token_required
def get_all_books(curent_user):
    books = Books.query.all()

    output = []
    for book in books:
        output.append({
            'isbn' : book.isbn,
            'title' : book.title,
            'publication_date' : book.publication_date,
            'edition' : book.edition,
            'quantity' : book.quantity,
            'price' : book.price,
            'author' : book.author,
            'publisher' : book.publisher,
        })
    return jsonify({
        'Books' : output
    })

@app.route('/books', methods = ['POST'])
def create():
    data = request.form

    isbn, title, publication_date, edition = data.get('isbn'), data.get('title'), data.get('publication_date'), data.get('edition')
    quantity, price = data.get('quantity'), data.get('price')
    author, publisher = data.get('author'), data.get('publisher')
    book = Books.query\
        .filter_by(isbn = isbn)\
        .first()
    
    if not book:
        book = Books(
            isbn = isbn,
            title = title,
            publication_date = publication_date,
            edition = edition,
            quantity = quantity,
            price = price,
            author = author,
            publisher = publisher,
        )

        db.session.add(book)
        db.session.commit()

        return make_response('Book successfully addesd!', 201)
    else:
        return make_response('Book laready exist', 202)

if __name__ == "__main__":
        app.run(debug = True)