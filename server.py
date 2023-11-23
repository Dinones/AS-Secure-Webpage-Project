from flask import Flask, render_template, request

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
            # Save the file to a specific folder (create the folder if it doesn't exist)
            upload_folder = '.'
            uploaded_file.save(f"{upload_folder}/CV.pdf")

            # Optionally, you can also do further processing with the uploaded PDF here

            print(f"Uploaded file saved: {uploaded_file.filename}")
            return 'File uploaded successfully!'
        else: return 'Invalid file format. Please upload a PDF.'
    return 'No file provided.'

if __name__ == '__main__':
    app.run(debug=True)
