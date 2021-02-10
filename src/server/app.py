from flask import Flask 
from dotenv import load_dotenv
import os
load_dotenv()

# Set up the app and point it to Vue
app = Flask(__name__, static_folder='../client/dist/',    static_url_path='/')

# Set up the index route
@app.route('/')
def index():
    return app.send_static_file('index.html')

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)