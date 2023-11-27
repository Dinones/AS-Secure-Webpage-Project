# Import the Flask class from the flask module
from flask import Flask

# Create an instance of the Flask class
app = Flask(__name__)

# Define a route for the home page
@app.route('/')
def home():
    return 'Hello, this is a simple placeholder website!'

# Run the application if the script is executed
if __name__ == '__main__':
    # Set debug=True for automatic reloading when you make changes to the code
    app.run(debug=True)
