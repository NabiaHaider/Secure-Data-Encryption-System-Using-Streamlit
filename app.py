# Zaroori libraries import kar rahe hain jo app ke kaam ke liye chahiye hoti hain

import streamlit as st  
# UI banane ke liye
import hashlib 
# passwords hash karne ke liye
import json  
# data file mein store aur load karne ke liye
import os
# file check karne ke liye
import time  
# lockout timer lagane ke liye

from cryptography.fernet import Fernet  # encryption/decryption ke liye
from base64 import urlsafe_b64encode, urlsafe_b64decode  # keys ko encode/decode karne ke liye
from hashlib import pbkdf2_hmac  # strong password hashing ke liye

# --- Constants ---
DATA_FILE = "secure_data.json"  # Ye file users ka data store karne ke liye use hoti hai
SALT = b"secure_salt_value"  # Password hashing mein extra security ke liye salt
LOCKOUT_DURATION = 60  # 60 seconds ka lock lagta hai agar 3 baar ghalat password dala

# --- Session State Initialization ---

# User login hai ya nahi, ye track karne ke liye
if "authentication_user" not in st.session_state:
    st.session_state.authentication_user = None

# Kitni baar ghalat login hua, ye track karne ke liye
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Jab lockout laga tha, us waqt ka time save hota hai
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# --- Helper Functions ---

# File se data load karta hai
def load_data():
    if os.path.exists(DATA_FILE):  # Agar file mojood hai
        with open(DATA_FILE, "r") as f:
            return json.load(f)  # Data return karo
    return {}  # Agar file nahi hai to khali dictionary return karo

# File mein updated data save karta hai
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# User ke password se encryption key banata hai (secure tariqa se)
def generate_key(password: str) -> bytes:
    key = pbkdf2_hmac(
        'sha256',  # hashing algorithm
        password.encode(),  # password ko bytes mein convert karo
        SALT,  # salt use karo
        100000  # itni baar hash apply karo (zyada security)
    )
    return urlsafe_b64encode(key)  # Key ko encode kar ke return karo

# Password ko securely hash karta hai
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Data ko encrypt karta hai (safe banata hai)
def encrypt_data(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

# Encrypted data ko decrypt karta hai (wapis original banata hai)
def decrypt_data(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None  # Agar decrypt na ho to None return karo

# Start mein data file se users ka data load kar rahe hain
stored_data = load_data()

# --- Streamlit UI ---

# App ka title
st.title("🔐 Secure Data Storage App")

# Sidebar menu banaya gaya hai
menu = ["🔑 Login", "📝 Register", "🏠 Home", "💾 Store Data", "🔓 Retrieve Data"]
choice = st.sidebar.selectbox("📁 Navigation", menu)

# Home page dikhata hai welcome message
if choice == "🏠 Home":
    st.subheader("👋 Welcome to the Secure Data Storage App")
    st.markdown("🔐  This app allows you to securely store and retrieve data using encryption.")

# User registration page
elif choice == "📝 Register":
    st.subheader("👤Create a New Account")
    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("✅ Register"):
        if username and password:  # Agar dono fields fill hain
            if username in stored_data:  # Agar user pehle se maujood hai
                st.error("⚠️Username already exists!")
            else:
                hashed_password = hash_password(password)  # Password ko hash karo
                stored_data[username] = hashed_password  # Save karo
                save_data(stored_data)
                st.success("🎉 Account created successfully! You can now log in.")
        else:
            st.error("❗ Please enter both username and password.")

# Login page
elif choice == "🔑 Login":
    st.subheader("🔑 Login to Your Accoun")
    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("🚪 Login"):
        current_time = time.time()
        
        # Lockout check karna agar 3 ghalat attempts ho chuki hain
        if st.session_state.failed_attempts >= 3 and (current_time - st.session_state.lockout_time) < LOCKOUT_DURATION:
            st.error(f"⏳Too many failed attempts. Please try again after {LOCKOUT_DURATION} seconds.")
        else:
            if username in stored_data:
                hashed_password = stored_data[username]
                if hash_password(password) == hashed_password:  # Correct password
                    st.session_state.authentication_user = username
                    st.success(f"✅ Welcome, {username}!")
                    st.session_state.failed_attempts = 0  # Reset failed attempts
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_time = current_time
                        st.error(f"🚫 Too many failed attempts. Please try again after {LOCKOUT_DURATION} seconds.")
                    else:
                        st.error("❌ Incorrect password. Please try again.")
            else:
                st.error("❌ Username not found. Please register first.")

# Data store karne ka page
elif choice == "💾 Store Data":
    if st.session_state.authentication_user:
        st.subheader("💾 Store Secure Data")
        key = st.text_input("🔑 Encryption Key", type="password")
        data_to_store = st.text_area("📄 Data to Store")

        if st.button("📥 Store Data"):
            if key and data_to_store:
                encrypted_data = encrypt_data(data_to_store, key)
                stored_data[st.session_state.authentication_user] = encrypted_data
                save_data(stored_data)
                st.success("✅  Data stored securely!")
            else:
                st.error("❗  Please enter both encryption key and data to store.")
    else:
        st.error("🔐 Please log in to store data.")

# Data wapis hasil karne ka page
elif choice == "🔓 Retrieve Data":
    if st.session_state.authentication_user:
        st.subheader("🔓 Retrieve Secure Data")
        key = st.text_input("🔑 Decryption Key", type="password")

        if st.button("📤 Retrieve Data"):
            if key:
                encrypted_data = stored_data.get(st.session_state.authentication_user)
                if encrypted_data:
                    decrypted_data = decrypt_data(encrypted_data, key)
                    if decrypted_data:
                        st.success("✅  Decrypted Data:")
                        st.text_area("📄", decrypted_data, height=200)
                    else:
                        st.error("❌ Invalid decryption key.")
                else:
                    st.error("📭 No data found for this user.")
            else:
                st.error("❗  Please enter the decryption key.")
    else:
        st.error("🔐Please log in to retrieve data.")
