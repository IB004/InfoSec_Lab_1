from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello!"

@app.route('/greet/<name>')
def greet(name):
    return f'Hello {name}!'

@app.route('/add/<int:n1>/<int:n2>')
def add(n1, n2):
    return f'{n1} + {n2} = {n1 + n2}!'

@app.route('/params', methods=['GET', 'POST'])
def params():
    if (request.method == 'GET'):
        return str(request.args)
    return 'POST!'


@app.route('/auth/login', methods=['POST'])
def login():
    username = request.json['username']
    return f'POST: {username}?!'


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

