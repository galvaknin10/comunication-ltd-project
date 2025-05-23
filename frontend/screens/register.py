import streamlit as st
import requests
import re
from screens.login import policy

API_URL = "http://backend:8000/register"
EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"
USERNAME_REGEX = r"^(?=.*[a-zA-Z]).{3,50}$"  # 3–50 characters, must include at least one letter

def show():
    st.title("📝 Register New User")

    # Input fields
    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    # Display password policy
    st.markdown(f"""
    🔐 **Password requirements:**
    - Minimum **{policy['min_length']}** characters  
    - {policy['guidelines']}
    """)

    if st.button("Register", key="register_submit"):
        # 1. Check for empty fields
        if not username or not email or not password:
            st.warning("All fields are required.")

        # 2. Validate username format
        elif not re.match(USERNAME_REGEX, username):
            st.warning("Username must be 3–50 characters long and include at least one letter.")

        # 3. Validate email format
        elif not re.match(EMAIL_REGEX, email):
            st.warning("Enter a valid email (e.g., name@example.com).")

        # 4. Validate password against policy
        elif len(password) < policy["min_length"]:
            st.warning(f"Password must be at least {policy['min_length']} characters long.")
        elif not re.match(policy["regex"], password):
            st.warning(f"{policy['guidelines']}")

        # 5. Send registration request
        else:
            try:
                response = requests.post(API_URL, json={
                    "username": username,
                    "email": email,
                    "password": password
                })
                if response.status_code == 200:
                    data = response.json()                      
                    st.success(data.get("message"))

                else:
                    detail = response.json().get("detail")
                    if isinstance(detail, list):
                        st.error(f"Error: {detail[0].get('msg', 'Unknown error')}")
                    else:
                        st.error(f"Error: {detail}")
            except Exception as e:
                st.error(f"Something went wrong: {e}")

    # Navigation: back to login screen
    if st.button("Back to login"):
        st.session_state.page = "login"
        st.rerun()
