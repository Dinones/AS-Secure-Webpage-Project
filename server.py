from flask import Flask, render_template, request, redirect, url_for, session, send_file
from check_pdf import is_valid_pdf, save_pdf
from enum import Enum
import pyodbc
import bcrypt
import os
import uuid
import secrets

#################################################################################################################

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generates a 32-character hex secret key

connection = None
cursor = None

# Dictionary to store active sessions (token, user)
active_sessions = {}

class UserInformation:
    def __init__(self, userMail, userID, userType):
        self.userMail = userMail
        self.userID = userID
        self.userType = userType


class UserType(Enum):
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
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType == UserType.APPLICANT: return render_template('applicant.html')
    else: return "ERROR: Logged user is not an applicant"

@app.route('/recruiter')
def recruiter():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType == UserType.RECRUITER: return render_template('recruiter.html')
    else: return "ERROR: Logged user is not a recruiter"

@app.route('/say_hello', methods=['POST'])
def say_hello():
    print("\nBaby hellooo! Fue por la historia que subiste a tu close!\n")
    return ''

@app.route('/check_credentials', methods=['POST'])
def check_credentials():
    username, password = request.form.get('username'), request.form.get('password')
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    print(f"Username: {username}, Unhashed-Password: {password}, Hashed-Password: {hashed_password}")
    userInfo = check_login(username, password)
    print(f'UserType: {UserType}')

    if userInfo.userType == 0: return redirect(url_for('home'))
    else:
        session_token = str(uuid.uuid4())
        active_sessions[session_token] = userInfo
        session['session_token'] = session_token

        if userInfo.userType == UserType.APPLICANT: return redirect(url_for('applicant'))
        else: return redirect(url_for('recruiter'))


@app.route('/upload', methods=['POST']) 
def upload():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if 'file' in request.files:
        uploaded_file = request.files['file']

        # Check if the file has a valid PDF extension
        if uploaded_file and uploaded_file.filename.endswith('.pdf'):
            uploaded_file.save(f"./temp_files/temp_CV.pdf")
            if not is_valid_pdf(f"./temp_files/temp_CV.pdf"): 
                os.remove(f"./temp_files/temp_CV.pdf")
                return 'ERROR: Invalid file format. Please upload a PDF.'
            upload_pdf_to_database(f"./temp_files/temp_CV.pdf", ActiveUser.userID)

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
        return UserInformation("", 0, 0)
    
    if bcrypt.checkpw(password.encode('utf-8'), rows[0][1].encode('utf-8')):
        userInfo = UserInformation(email, rows[0][0], 0)
        if rows[0][2] == 'Recruiter': userInfo.userType = UserType.RECRUITER 
        else: userInfo.userType = UserType.APPLICANT
        return userInfo 
    else: 
        print('ERROR: Password did not match!')
        return UserInformation("", 0, 0)

def upload_pdf_to_database(pdf_path, userID):
    global cursor, connection

    try:
        with open(pdf_path, 'rb') as file:
            cursor.execute(f"UPDATE Applicant SET [CV] = (?) WHERE UserID = {userID}", file.read())
        connection.commit()
        print("File successfully updated!")
    except pyodbc.Error as e: 
        print(f"Error uploading file to the database: {e}")
    os.remove(pdf_path)

def download_pdf_from_database(userID, output_pdf_path = './temp_files/temp_CV.pdf'):
    global cursor, connection

    cursor.execute(f"SELECT [CV] FROM Applicant WHERE UserID = {userID}")
    row = cursor.fetchone()
    if row:
        with open(output_pdf_path, 'wb') as file:
            file.write(row[0])

@app.route('/send_document_to_user')
def send_document_to_user():
    download_pdf_from_database(2)
    document_path = './temp_files/temp_CV.pdf'
    document_name = 'CV.pdf'

    # Send the file to the user for download
    return send_file(document_path, as_attachment=True, attachment_filename=document_name)

#################################################################################################################

if __name__ == '__main__':
    connect_to_database()
    try: app.run(debug=True)
    except: disconnect_from_database()