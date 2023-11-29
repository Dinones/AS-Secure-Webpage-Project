'''
registration / login:
pwd -> PBKDF2 -> K (seed of PRNG) -> (sk, pk) of user [ -> store pk in db ]

upload:
CV -> random key -> encrypt CV -> store ciphertext in db
                 -> encrypt key with user pk -> store encrypted key in db

send CV:
encrypted key in db -> decrypt with sk -> encrypt with recruiter pk -> store encrypted key in db

user forgotten pwd (import backup key?):
"For security reasons, your files were deleted."
if CV sent to recruiter -> delete key encrypted with user's sk
if CV unsent -> delete CV and the key encrypted with user's sk

recruiter forgotten pwd (backup recruiter mechanism):
if no CVs received -> regenerate (sk, pk)
if CVs received -> alert backups to log in and automatically create encrypted key

user data encryption:
the same random key as for CV
'''

import random
import base64
from pypdf import PdfReader, PdfWriter
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES, PKCS1_OAEP

'''
Notation:
S - session info
DB - db info
D - displayed info (in the webpage)
'''

#USE
#call also for registration
#in: password hash, user data <array> (needed only for registration), encrypted symmetric key (None in case of registration)
#out: user sk (S), user pk (in case of registration DB), encrypted user data <array> (in case of registration DB), encrypted key (in case of registration DB), symmetric key (S)
def login(hash_pwd, udata=None, enc_key=None):
    dp2 = 2 + hash_pwd[1:].find('$')
    dp3 = 1 + dp2 + hash_pwd[dp2:].find('$')
    pbkdf_salt = base64.b64decode(hash_pwd[dp3:])[:16]
    seed = PBKDF2(pwd, pbkdf_salt, 16, 100000, hmac_hash_module=SHA256)
    random.seed(seed)
    user_sk = RSA.generate(bits=2048, randfunc=random.randbytes)
    user_pk = user_sk.public_key()
    if enc_key == None:
        enc_udata, sym_key = encrypt_udata(udata)
        rsa = PKCS1_OAEP.new(user_pk)
        enc_key = rsa.encrypt(sym_key)
    else:
        enc_udata = None
        rsa = PKCS1_OAEP.new(user_sk)
        sym_key = rsa.decrypt(enc_key)
    return user_sk, user_pk, enc_udata, enc_key, sym_key

#DON'T USE
#called only once after registration (in the login function)
#in: user data <array>
#out: encrypted user data <array>, symmetric key
def encrypt_udata(udata):
    aes_key = get_random_bytes(16)
    aes = AES.new(aes_key, AES.MODE_GCM)
    nonce = aes.nonce
    sym_key = aes_key + nonce
    enc_udata = []
    for data in udata:
        enc_data = aes.encrypt(bytes(data, 'utf-8'))
        enc_udata.append(enc_data)
    return enc_udata, sym_key

#USE
#in: encrypted user data <array>, symmetric key
#out: user data <array> (D)
def decrypt_udata(enc_udata, sym_key):
    aes_key = sym_key[:16]
    nonce = sym_key[16:]
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    udata = []
    for enc_data in enc_udata:
        data = aes.decrypt(enc_data).decode('utf-8')
        udata.append(data)
    return udata

#USE
#in: symmetric key, input file name, output file name
#out: None
def upload_CV(sym_key, file_path_in, file_path_out):
    reader = PdfReader(file_path_in)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(sym_key, algorithm="AES-256-R5")
    with open(file_path_out, "wb") as f:
        writer.write(f)
    return

#USE
#call also as a recruiter
#in: encrypted symmetric key, user sk, input file name, output file name
#out: None
def get_CV(enc_key, user_sk, file_path_in, file_path_out):
    rsa = PKCS1_OAEP.new(user_sk)
    sym_key = rsa.decrypt(enc_key)
    reader = PdfReader(file_path_in)
    writer = PdfWriter()
    if reader.is_encrypted:
        reader.decrypt(sym_key)
    for page in reader.pages:
        writer.add_page(page)
    with open(file_path_out, "wb") as f:
        writer.write(f)
    return

#USE
#in: symmetric key, recruiter pk
#out: encrypted symmetric key (DB)
def share_CV(sym_key, recruiter_pk):
    rsa = PKCS1_OAEP.new(recruiter_pk)
    enc_key = rsa.encrypt(sym_key)
    return enc_key


user = "larryka@gmail.com"
name = "Larry"
pwd = "password123"
hash_pwd = "$2b$12$qni37LHcVYDi6NZzBUN7/uwSPf2xPj.VeOkIjc6nLt1CqWF8EUBqe"


#EXAMPLE REGISTRATION
udata = [user, name, pwd]
user_sk, user_pk, enc_udata, enc_key, sym_key = login(hash_pwd, udata)
#udata = decrypt_udata(enc_udata, sym_key)
#upload_CV(sym_key, "CV.pdf", "enc_CV.pdf")
#get_CV(enc_key, user_sk, "enc_CV.pdf", "dec_CV.pdf")
#enc_key = share_CV(sym_key, user_pk)
#get_CV(enc_key, user_sk, "enc_CV.pdf", "dec_CV.pdf")

#EXAMPLE LOGIN
user_sk, user_pk, _, _, sym_key = login(hash_pwd, udata=None, enc_key=enc_key)
udata = decrypt_udata(enc_udata, sym_key)
upload_CV(sym_key, "CV.pdf", "enc_CV.pdf")
#get_CV(enc_key, user_sk, "enc_CV.pdf", "dec_CV.pdf")
enc_key = share_CV(sym_key, user_pk)
get_CV(enc_key, user_sk, "enc_CV.pdf", "dec_CV.pdf")


'''
#registration/login
dp2 = 2 + hash_pwd[1:].find('$')
dp3 = 1 + dp2 + hash_pwd[dp2:].find('$')
pbkdf_salt = base64.b64decode(hash_pwd[dp3:])[:16]
seed = PBKDF2(pwd, pbkdf_salt, 16, 100000, hmac_hash_module=SHA256)
random.seed(seed)
user_sk = RSA.generate(bits=2048, randfunc=random.randbytes)
user_pk = user_sk.public_key()
##store user_pk in db if registering

#user data encryption
##read user_field from db
user_field = pwd
aes_key = get_random_bytes(16)
aes = AES.new(aes_key, AES.MODE_GCM)
nonce = aes.nonce
enc_field = aes.encrypt(bytes(user_field, 'utf-8'))
##store nonce and enc_field in db

#user data decryption
##read enc_field from db
aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
user_field = aes.decrypt(enc_field).decode('utf-8')
##display user_field

#upload
CV_key = aes_key
rsa = PKCS1_OAEP.new(user_pk)
enc_key = rsa.encrypt(CV_key)
reader = PdfReader("CV.pdf")
writer = PdfWriter()
for page in reader.pages:
    writer.add_page(page)
writer.encrypt(CV_key+nonce, algorithm="AES-256-R5")
with open("encrypted-pdf.pdf", "wb") as f:
    writer.write(f)
##store pdf in db
##store enc_key in db

#download
##read pdf from db
rsa = PKCS1_OAEP.new(user_sk)
CV_key = rsa.decrypt(enc_key)
reader = PdfReader("encrypted-pdf.pdf")
writer = PdfWriter()
if reader.is_encrypted:
    reader.decrypt(CV_key)
for page in reader.pages:
    writer.add_page(page)
with open("decrypted-pdf.pdf", "wb") as f:
    writer.write(f)
##display the CV to the user (or recruiter)

#send
##read recruiter_pk from db
recruiter_pk = user_pk
rsa = PKCS1_OAEP.new(user_sk)
CV_key = rsa.decrypt(enc_key)
rsa = PKCS1_OAEP.new(recruiter_pk)
enc_key = rsa.encrypt(CV_key)
##store enc_key in db for recruiter
'''
