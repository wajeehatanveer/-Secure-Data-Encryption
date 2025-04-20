import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Session state setup
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# Utility Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key():
    return Fernet.generate_key()

def encrypt_text(text, key):
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt_text(ciphertext, key):
    f = Fernet(key)
    return f.decrypt(ciphertext.encode()).decode()

# --- Login Page ---
def login_page():
    st.title("🔐 Reauthorization Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        # Simple static login (can be extended)
        if username == "admin" and password == "admin123":
            st.success("Login successful!")
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
        else:
            st.error("Incorrect credentials.")

# --- Insert Data Page ---
def insert_data_page():
    st.title("📝 Insert New Data")

    key_name = st.text_input("Enter a name to store the data under:")
    text = st.text_area("Enter the text to encrypt:")
    passkey = st.text_input("Enter a passkey (used to protect your data):", type="password")

    if st.button("Encrypt & Store"):
        if key_name and text and passkey:
            hashed = hash_passkey(passkey)
            fernet_key = Fernet.generate_key()
            encrypted_text = encrypt_text(text, fernet_key)
            st.session_state.stored_data[key_name] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed,
                "fernet_key": fernet_key.decode()
            }
            st.success(f"Data stored securely under '{key_name}'")
        else:
            st.warning("Please fill in all fields.")

# --- Retrieve Data Page ---
def retrieve_data_page():
    st.title("🔓 Retrieve Encrypted Data")

    key_name = st.text_input("Enter the key name:")
    passkey = st.text_input("Enter the passkey:", type="password")

    if st.session_state.failed_attempts >= 3:
        st.warning("Too many failed attempts. Please login again.")
        st.session_state.authorized = False
        return

    if st.button("Retrieve"):
        if key_name in st.session_state.stored_data:
            stored_entry = st.session_state.stored_data[key_name]
            hashed_input = hash_passkey(passkey)

            if hashed_input == stored_entry["passkey"]:
                decrypted = decrypt_text(
                    stored_entry["encrypted_text"],
                    stored_entry["fernet_key"].encode()
                )
                st.success("Data successfully decrypted:")
                st.code(decrypted)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error("Incorrect passkey.")
                st.info(f"Failed attempts: {st.session_state.failed_attempts}/3")
        else:
            st.error("No data found with that key.")

# --- Home Page ---
def home_page():
    st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒")
    st.title("🔒Secure Data Encryption System")
    choice = st.radio("Choose an option:", ["Insert New Data", "Retrieve Data"])

    if choice == "Insert New Data":
        insert_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()

# --- App Router ---strelit run main.py
if st.session_state.authorized:
    home_page()
else:
    login_page()
