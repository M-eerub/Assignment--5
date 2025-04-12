import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Setup ---

# Generate a key once and use it to create Fernet object
# (In real apps, save the key somewhere safe!)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory dictionary to store encrypted data
stored_data = {}
failed_attempts = 0  # Track failed decryption attempts

# --- Helper Functions ---

# Hash the passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt the text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt the text if passkey matches
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    # Search for matching entry
    if encrypted_text in stored_data:
        saved = stored_data[encrypted_text]
        if saved["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None

# --- Streamlit App UI ---

st.title("🔐 Simple Secure Data Vault")

# Navigation menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

# Home Page
if choice == "Home":
    st.write("Welcome! Use this app to securely store and retrieve your private data using a secret passkey.")

# Store Data Page
elif choice == "Store Data":
    st.subheader("📥 Store Your Data Securely")
    text = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Set a secret passkey:", type="password")

    if st.button("Encrypt and Save"):
        if text and passkey:
            encrypted = encrypt_data(text)
            stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hash_passkey(passkey)
            }
            st.success("✅ Your data has been encrypted and stored.")
            st.code(encrypted, language='text')
        else:
            st.warning("⚠️ Please enter both text and passkey.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Your Data")
    encrypted_input = st.text_area("Paste your encrypted data here:")
    passkey = st.text_input("Enter your secret passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Success! Here's your decrypted data:")
                st.code(result, language='text')
            else:
                attempts_left = max(0, 3 - failed_attempts)
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")

                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Redirecting to Login Page...")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Please enter both fields.")

# Login Page for reauthorization
elif choice == "Login":
    st.subheader("🔑 Login Required")
    master_password = st.text_input("Enter master password to reset attempts:", type="password")

    if st.button("Login"):
        if master_password == "admin123":  # Replace with secure logic in real apps
            failed_attempts = 0
            st.success("✅ Access granted. You may now retry decryption.")
            st.experimental_rerun()
        else:
            st.error("❌ Wrong master password.")
