from flask import Flask, render_template, request
from check_pdf import is_valid_pdf, save_pdf

app = Flask(__name__, template_folder='webfiles')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/say_hello', methods=['POST'])
def say_hello():
    print("\nBaby hellooo! Fue por la historia que subiste a tu close!\n")
    return ''

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' in request.files:
        uploaded_file = request.files['file']

        # Check if the file has a valid PDF extension
        if uploaded_file and uploaded_file.filename.endswith('.pdf'):
            uploaded_file.save(f"temp_files/temp_CV.pdf")
            is_valid_pdf(f"temp_files/temp_CV.pdf")
            if not save_pdf(): return 'ERROR: There was an error saving the file. Please, try again.'

            print(f"\nUploaded file saved: {uploaded_file.filename}\n")
            return 'File uploaded successfully!'
        else: return 'ERROR: Invalid file format. Please upload a PDF.'
    return 'ERROR: No file provided.'

if __name__ == '__main__':
    app.run(debug=True)
