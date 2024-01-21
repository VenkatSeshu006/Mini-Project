from flask import Flask, render_template, request, jsonify
import os
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_symmetric_key(sym_key, receiver_public_key):
    cipher_text = receiver_public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    return cipher_text

def encrypt_file(file_path, sym_key):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(sym_key), modes.CFB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    receiver_public_key = rsa.PublicKey.load_pem_x509_certificate(
        request.form['public_key'].encode(),
        backend=default_backend()
    )

    sym_key = secrets.token_bytes(16)  # 128 bits (16 bytes) key for AES
    cipher_text_key = encrypt_symmetric_key(sym_key, receiver_public_key)
    ciphertext = encrypt_file(file.filename, sym_key)

    file_name = secrets.token_hex(8) + '_' + file.filename
    file_path = os.path.join('static/uploads', file_name)

    with open(file_path, 'wb') as file:
        file.write(ciphertext)

    return jsonify({'message': 'File successfully uploaded', 'file_path': file_path})

if __name__ == '__main__':
    app.run(debug=True)
