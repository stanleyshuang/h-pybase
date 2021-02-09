from flask import Flask, request

app = Flask(__name__)


@app.route('/')
def hello():
    return f'Hello, world!'

if __name__ == 'main':
    app.run()