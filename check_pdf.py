import fitz  # PyMuPDF

def is_valid_pdf(file_path):
    try:
        with fitz.open(file_path) as pdf_document:
            # Accessing the first page to check if the document is valid
            pdf_page = pdf_document[0]
            return pdf_page is not None
    except Exception as e:
        # An exception will be raised if the file is not a valid PDF
        return False

# Example usage
file_path = "CV.pdf"
if is_valid_pdf(file_path): print(f"The file '{file_path}' is a valid PDF.")
else: print(f"The file '{file_path}' is not a valid PDF.")
