from flask import Flask, render_template, request, redirect, url_for
from check_pdf import is_valid_pdf, save_pdf
from enum import Enum
import pyodbc
import bcrypt
import os

#################################################################################################################

app = Flask(__name__, template_folder='templates', static_folder='static')
connection = None
cursor = None

class User(Enum):
    APPLICANT = 1
    RECRUITER = 2

#################################################################################################################

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/applicant')
def applicant():
    return render_template('applicant.html')

@app.route('/recruiter')
def recruiter():
    return render_template('recruiter.html')

@app.route('/say_hello', methods=['POST'])
def say_hello():
    print("\nBaby hellooo! Fue por la historia que subiste a tu close!\n")
    return ''

@app.route('/check_credentials', methods=['POST'])
def check_credentials():
    username, password = request.form.get('username'), request.form.get('password')
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    print(f"Username: {username}, Unhashed-Password: {password}, Hashed-Password: {hashed_password}")
    UserType = check_login(username, password)
    print(f'UserType: {UserType}')

    if UserType == 0: return redirect(url_for('home'))
    elif UserType == 1: return redirect(url_for('applicant'))
    else: return redirect(url_for('recruiter'))


@app.route('/upload', methods=['POST']) 
def upload():
    if 'file' in request.files:
        uploaded_file = request.files['file']

        # Check if the file has a valid PDF extension
        if uploaded_file and uploaded_file.filename.endswith('.pdf'):
            uploaded_file.save(f"temp_files/temp_CV.pdf")
            if not is_valid_pdf(f"temp_files/temp_CV.pdf"): 
                os.remove(f"temp_files/temp_CV.pdf")
                return 'ERROR: Invalid file format. Please upload a PDF.'
            save_pdf()
            upload_pdf('./CV.pdf')
            download_pdf()

            print(f"\nUploaded file saved: {uploaded_file.filename}\n")
            return 'File uploaded successfully!'
        else: return 'ERROR: Invalid file format. Please upload a PDF.'
    return 'ERROR: No file provided.'

#################################################################################################################

def connect_to_database():
    global cursor, connection
    server = 'MSI'
    database = 'as'
    username = 'aleix'
    password = 'aleix123'

    # Define the connection string
    connection_string = f'DRIVER=SQL Server;SERVER={server};DATABASE={database};UID={username};PWD={password}'

    try:
        # Establish a connection to the database
        connection = pyodbc.connect(connection_string)
        # Create a cursor from the connection
        cursor = connection.cursor()
        print("Connected to the database!")
    except pyodbc.Error as e:
        print(f"Error connecting to the database: {e}")

def disconnect_from_database():
    global cursor, connection

    try:
        cursor.close()
        connection.close()
    except pyodbc.Error as e: 
        print(f"Error disconnecting from the database: {e}")

def check_login(email, password):
    global cursor, connection

    cursor.execute(f"SELECT UserID, PasswordHash, UserType FROM MainUser WHERE Email = '{email}'")
    rows = cursor.fetchall()
    if len(rows) != 1: 
        print('ERROR: Command did not return a single row!')
        return 0
    
    if bcrypt.checkpw(password.encode('utf-8'), rows[0][1].encode('utf-8')):
        return User.RECRUITER.value if rows[0][2] == 'Recruiter' else User.APPLICANT.value
    else: return 0

def upload_pdf(pdf_path):
    global cursor, connection

    try:
        with open(pdf_path, 'rb') as file:
            cursor.execute(f"UPDATE Applicant SET [CV] = (?) WHERE UserID = 1", file.read())
        connection.commit()
        print("File successfully updated!")
    except pyodbc.Error as e: 
        print(f"Error uploading file to the database: {e}")

def download_pdf(output_pdf_path = './DOWNLOADED_CV.pdf'):
    global cursor, connection

    cursor.execute(f"SELECT [CV] FROM Applicant WHERE UserID = 1")
    row = cursor.fetchone()
    if row:
        with open(output_pdf_path, 'wb') as file:
            file.write(row[0])

#################################################################################################################

if __name__ == '__main__':
    connect_to_database()
    try: app.run(debug=True)
    except: disconnect_from_database()