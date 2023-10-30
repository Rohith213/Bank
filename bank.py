import streamlit as st
from pymongo import MongoClient
import bcrypt

# Connect to the MongoDB database
client = MongoClient("mongodb://localhost:27017/")
db = client["bank_app"]
users_collection = db["users"]

# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed

# Function to verify a password
def verify_password(stored_password, input_password):
    return bcrypt.checkpw(input_password.encode("utf-8"), stored_password)

# Function to check the user's balance
def check_balance(username):
    user = users_collection.find_one({"username": username})
    if user:
        return user["balance"]
    else:
        return None

# Streamlit app
def main():
    st.title("Bank Application")

    # Sidebar navigation
    page = st.sidebar.selectbox("Select a page", ["Login", "Signup", "Check Balance"])

    if page == "Login":
        st.header("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            user = users_collection.find_one({"username": username})
            if user and verify_password(user["password"], password):
                st.success(f"Logged in as {username}")
            else:
                st.error("Invalid credentials. Please try again.")

    elif page == "Signup":
        st.header("Signup")
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        
        if st.button("Signup"):
            if new_username and new_password:
                existing_user = users_collection.find_one({"username": new_username})
                if existing_user:
                    st.error("Username already exists. Please choose a different one.")
                else:
                    hashed_password = hash_password(new_password)
                    users_collection.insert_one({"username": new_username, "password": hashed_password, "balance": 0})
                    st.success("Account created successfully. You can now log in.")

    elif page == "Check Balance":
        st.header("Check Balance")
        username = st.text_input("Username")
        
        if st.button("Check Balance"):
            balance = check_balance(username)
            if balance is not None:
                st.success(f"Balance for {username}: ${balance}")
            else:
                st.error(f"User '{username}' not found.")

if __name__ == "__main__":
    main()
