import os
import fitz # PyMuPDF

def is_valid_pdf(file_path):
    try:
        with fitz.open(file_path) as pdf_document:
            # Access the first page to check if the document is valid
            pdf_page = pdf_document[0]
            return pdf_page is not None
    except Exception:
        # An exception will be raised if the file is not a valid PDF
        return False

def save_pdf(destination_path = './CV.pdf'): 
    try:
        if os.path.exists(destination_path): os.remove(destination_path)
        os.rename('./temp_files/temp_CV.pdf', destination_path)
        return True
    except EOFError: 
        # print(EOFError)
        return False

if __name__ == "__main__":
    file_path = "CV.pdf"
    if is_valid_pdf(file_path): print(f"The file '{file_path}' is a valid PDF.")
    else: print(f"The file '{file_path}' is not a valid PDF.")