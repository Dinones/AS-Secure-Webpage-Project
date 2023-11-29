from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from check_pdf import is_valid_pdf, save_pdf
from enum import Enum
from enc_AS import *
import pyodbc
import bcrypt
import os
import uuid
import secrets
import binascii

#################################################################################################################

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generates a 32-character hex secret key

connection = None
cursor = None

# Dictionary to store active sessions (token, user)
active_sessions = {}

class UserInformation:
    def __init__(self, userMail, userID, userType, privateKey, symmetricKey):
        self.userMail = userMail
        self.userID = userID
        self.userType = userType
        self.privateKey = privateKey
        self.symmetricKey = symmetricKey


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

@app.route('/user_profile')
def user_profile():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType == UserType.APPLICANT: return render_template('user-info.html')
    else: return "ERROR: Logged user is not an applicant"

@app.route('/job')
def job():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType == UserType.APPLICANT: return render_template('job.html')
    else: return "ERROR: Logged user is not an applicant"

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
    print("\nHello World!\n")
    return ''

@app.route('/check_credentials', methods=['POST'])
def check_credentials():
    username, password = request.form.get('username'), request.form.get('password')

    print(f"Username: {username}, Unhashed-Password: {password}")
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

@app.route('/get_job_offers_applicant', methods=['GET'])
def get_job_offers_applicant():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType != UserType.APPLICANT: return "ERROR: Logged user is not an applicant"

    job_offers = get_job_offers_from_database_for_applicant(ActiveUser.userID)

    # print(job_offers)

    return jsonify(job_offers)

@app.route('/apply_to_offer', methods=['POST'])
def apply_to_offer():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType != UserType.APPLICANT: return "ERROR: Logged user is not an applicant"

    data = request.get_json()
    if 'title' in data:
        offer_title = data['title']
        print(f"Applying to offer: {offer_title}")
    else: return jsonify({'error': 'Invalid request'})

    if apply_to_offer_database(ActiveUser.userID, offer_title): return jsonify({'redirect': url_for('applicant')})
    else: return jsonify({'error': 'Could not apply to job offer'})

@app.route('/get_recruiter_applicants', methods=['GET'])
def get_recruiter_applicants():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType != UserType.RECRUITER: return "ERROR: Logged user is not a recruiter"

    recruiters = get_recruiter_applicants_from_database(ActiveUser.userID)

    return jsonify(recruiters)

@app.route('/get_user_info', methods=['GET'])
def get_user_info():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType != UserType.APPLICANT: return "ERROR: Logged user is not an applicant"

    applicant_info = get_user_info_from_database(ActiveUser.userID)

    return jsonify(applicant_info)

#################################################################################################################

def connect_to_database():
    global cursor, connection
    server = 'FERRANPALMADAPC'
    database = 'as'
    username = 'ferran'
    password = 'ferran123'

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

    cursor.execute(f"SELECT UserID, PasswordHash, EncryptedSymmetricKey, UserType FROM MainUser WHERE Email = ?", email)
    rows = cursor.fetchall()
    if len(rows) != 1: 
        print('ERROR: Command did not return a single row!')
        return UserInformation("", 0, 0, "", "")
    
    if bcrypt.checkpw(password.encode('utf-8'), rows[0][1].encode('utf-8')):
        # Create keys and add them to the UserInformation

        print(rows[0][2])

        user_sk, _, _, _, sym_key = login(password, rows[0][1], None, rows[0][2])

        userInfo = UserInformation(email, rows[0][0], 0, user_sk, sym_key)

        if rows[0][3] == 'Recruiter': userInfo.userType = UserType.RECRUITER 
        else: userInfo.userType = UserType.APPLICANT
        return userInfo 
    else: 
        print('ERROR: Password did not match!')
        return UserInformation("", 0, 0, "", "")

def upload_pdf_to_database(pdf_path, userID):
    global cursor, connection

    sym_key = active_sessions[session['session_token']].symmetricKey
    upload_CV(sym_key, pdf_path, pdf_path)

    try:
        with open(pdf_path, 'rb') as file:
            cursor.execute(f"UPDATE Applicant SET [CV] = (?) WHERE UserID = ?", file.read(), userID)
        connection.commit()
        print("File successfully updated!")
    except pyodbc.Error as e: 
        print(f"Error uploading file to the database: {e}")
    #os.remove(pdf_path)

'''
def download_pdf_from_database(userID, output_pdf_path = './temp_files/temp_CV.pdf'):
    global cursor, connection

    cursor.execute(f"SELECT [CV] FROM Applicant WHERE UserID = ?", userID)
    row = cursor.fetchone()
    if row:
        with open(output_pdf_path, 'wb') as file:
            file.write(row[0])
'''

def download_email_pdf_from_database(userMail, output_pdf_path = './temp_files/temp_CV.pdf'):
    global cursor, connection

    cursor.execute(f"SELECT AP.CV FROM Applicant AP JOIN MainUser MU ON AP.UserID = MU.UserID WHERE MU.Email = ?;", userMail)
    row = cursor.fetchone()
    if row:
        with open(output_pdf_path, 'wb') as file:
            file.write(row[0])

        userID = active_sessions[session['session_token']].userID
        cursor.execute("SELECT OA.CV_EncryptedKey FROM OfferApplicant OA JOIN Offer O ON O.OfferID = OA.OfferID JOIN Recruiter R ON O.RecruiterID = R.UserID JOIN MainUser MU ON OA.UserID = MU.UserID WHERE R.UserID = ? AND MU.Email = ?;", userID, userMail)
        
        row = cursor.fetchone()

        user_sk = active_sessions[session['session_token']].privateKey

        get_CV(row[0], user_sk, output_pdf_path, output_pdf_path)
        
    else: print('ERROR: Not CV found')

@app.route('/send_document_to_user', methods=['POST'])
def send_document_to_user():
    if 'session_token' in session:
        session_token = session['session_token']

        if session_token in active_sessions:
            ActiveUser = active_sessions[session_token]
            print(f"Active user's mail is {ActiveUser.userMail}, with ID = {ActiveUser.userID}")
        else: return 'ERROR: Invalid session.'
    else: return 'ERROR: Not logged in.'

    if ActiveUser.userType != UserType.RECRUITER: return "ERROR: Logged user is not a recruiter"

    data = request.get_json()
    if 'Email' in data:
        applicant_email = data['Email']
        print(f"Applying to offer: {applicant_email}")
    else: return jsonify({'error': 'Invalid request'})
    print(applicant_email)

    download_email_pdf_from_database(applicant_email)
    document_path = './temp_files/temp_CV.pdf'
    document_name = 'CV.pdf'

    # return send_file(document_path, as_attachment=True, attachment_filename=document_name)
    return send_file(document_path, as_attachment=True, download_name=document_name)

def get_job_offers_from_database_for_applicant(userID):
    global cursor, connection

    print("Getting job offers for applicant...")
    cursor.execute(f"SELECT O.OfferTitle, O.OfferDescription, CASE WHEN OA.UserID IS NOT NULL THEN 1 ELSE 0 END AS IsRelated FROM Offer O LEFT JOIN OfferApplicant OA ON O.OfferID = OA.OfferID AND OA.UserID = ?;", userID)

    rows = cursor.fetchall()

    jobOffers = []
    for row in rows:
        dictionary = {}
        dictionary['title'] = row[0]
        dictionary['description'] = row[1]
        dictionary['alreadyApplied'] = row[2]
        jobOffers.append(dictionary)

    return jobOffers


def apply_to_offer_database(userID, jobTitle):
    global cursor, connection
    try:
        print("Getting job offers for applicant...")

        cursor.execute(f"SELECT MU.UserPublicKey, O.OfferID FROM MainUser MU JOIN Recruiter R ON MU.UserID = R.UserID JOIN Offer O ON O.RecruiterID = R.UserID WHERE O.OfferTitle = ?;", jobTitle)
        row = cursor.fetchone()
        if row:
            with open('temp_public_key.pem', 'wb') as file:
                file.write(row[0])
        else: print('ERROR: No public key found')

        sym_key = active_sessions[session['session_token']].symmetricKey

        enc_key = share_CV(sym_key, "temp_public_key.pem")

        os.remove("temp_public_key.pem")

        #cursor.execute("INSERT INTO OfferApplicant (OfferID, UserID, CV_EncryptedKey) SELECT O.OfferID, A.UserID FROM Offer O JOIN Applicant A ON A.UserID = ? WHERE O.OfferTitle = ?;", userID, jobTitle, enc_key)
        cursor.execute("INSERT INTO OfferApplicant (OfferID, UserID, CV_EncryptedKey) VALUES (?, ?, ?)", row[1], userID, enc_key)

        connection.commit()
    except pyodbc.Error as e:
        print(f"Error inserting relationship: {e}")
        return False

    return True

def get_recruiter_applicants_from_database(userID):
    global cursor, connection

    print("Getting job offers for applicant...")
    cursor.execute(f"SELECT MU.EncryptedFirstName AS FirstName, \
                            MU.EncryptedLastName AS LastName, \
                            O.OfferTitle AS Applied, \
                            MU.Email AS Email, \
                            MU.EncryptedTelephoneNumber AS TelephoneNumber, \
                            OA.CV_EncryptedKey \
                    FROM OfferApplicant OA JOIN Offer O ON OA.OfferID = O.OfferID JOIN MainUser MU ON OA.UserID = MU.UserID WHERE O.recruiterID = ?;", userID)

    rows = cursor.fetchall()


    applicants = []
    for row in rows:
        # Decrypt user data
        user_data = [row[0], row[1], row[4]]
        user_data = decrypt_udata(user_data, row[5], active_sessions[session['session_token']].privateKey)

        dictionary = {}
        dictionary['Name'] = user_data[0] + " " + user_data[1]
        dictionary['Applied'] = row[2]
        dictionary['Email'] = row[3]
        dictionary['TelephoneNumber'] = user_data[2]
        applicants.append(dictionary)

    return applicants

def get_user_info_from_database(userID):
    global cursor, connection

    print("Getting applicant info...")
    cursor.execute(f"SELECT EncryptedFirstName, EncryptedLastName, Email, EncryptedTelephoneNumber, EncryptedSymmetricKey FROM MainUser WHERE UserID = ?", userID)
    row = cursor.fetchone()

    user_data = [row[0], row[1], row[3]]
    user_data = decrypt_udata(user_data, row[4], active_sessions[session['session_token']].privateKey)

    applicant_info = {}

    applicant_info['First name'] = user_data[0]
    applicant_info['Last name'] = user_data[1]
    applicant_info['Email'] = row[2]
    applicant_info['TelephoneNumber'] = user_data[2]

    return applicant_info

def upload_key_userID_database(key_path, userID):
    global cursor, connection

    try:
        with open(key_path, 'rb') as file:
            cursor.execute(f"UPDATE MainUser SET PublicKey = (?) WHERE UserID = ?", file.read(), userID)
        connection.commit()
        print("File successfully updated!")
    except pyodbc.Error as e: 
        print(f"Error uploading file to the database: {e}")


def download_key_userID_database(userID, output_pdf_path = './temp_files/temp_CV.pdf'):
    global cursor, connection

    cursor.execute(f"SELECT PublicKey FROM MainUser WHERE UserID = ?;", userID)
    row = cursor.fetchone()
    if row:
        with open(output_pdf_path, 'wb') as file:
            file.write(row[0])
    else: print('ERROR: Not CV found')




#################################################################################################################

if __name__ == '__main__':

    print("RUNNING MAIN")

    connect_to_database()

    ####### THIS CODE UPLOADS THE SampleKeys\ FILES TO THE DATABASE #######

    #with open('database\SampleKeys\public_key_user1.pem', 'rb') as file:
    #    cursor.execute(f"UPDATE MainUser SET UserPublicKey = (?) WHERE UserID = 1", file.read())
    #connection.commit()
#
    #with open('database\SampleKeys\public_key_user2.pem', 'rb') as file:
    #    cursor.execute(f"UPDATE MainUser SET UserPublicKey = (?) WHERE UserID = 2", file.read())
    #connection.commit()
#
    #with open('database\SampleKeys\public_key_user3.pem', 'rb') as file:
    #    cursor.execute(f"UPDATE MainUser SET UserPublicKey = (?) WHERE UserID = 3", file.read())
    #connection.commit()
    
    ########################################################################
    
    '''
    cursor.execute("SELECT * FROM MainUser;")

    rows = cursor.fetchall()

    passwords = ["password123", "1234", "admins"]
    i = 0
    for row in rows:
        user_data = [row[2], row[3], row[5]]
        _, user_pk_path, enc_user_data, enc_key, _ = login(passwords[i], row[1], user_data, None)

        print(f"User {i+1}: User data: {[binascii.hexlify(element).decode('utf-8') for element in enc_user_data]}, key: {binascii.hexlify(enc_key).decode('utf-8')}")
        
        i += 1
        # hex_array = [binascii.hexlify(element).decode('utf-8') for element in enc_user_data]

    '''


    try: app.run(debug=True)
    #try: app.run(debug=True, ssl_context=('./certificates/cert.pem', './certificates/key.pem'))
    except: disconnect_from_database()
    #try: app.run(debug=True)



    # try: app.run(debug=True, ssl_context=('./certificates/cert.pem', './certificates/key.pem'))
    #except: disconnect_from_database()
    
