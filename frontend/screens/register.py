import streamlit as st
import requests
import re
from screens.login import policy


API_URL = "http://backend:8000/register"

def show():
    st.title("📝 Register New User")

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    st.markdown(f"""
    🔐 **Password requirements:**
    - Minimum **{policy['min_length']}** characters  
    - {policy['guidelines']}
    """)


    if st.button("Register", key="register_submit"):
        if len(password) < policy["min_length"]:
            st.warning(f"Password must be at least {policy['min_length']} characters long")
        elif not re.match(policy['regex'], password):
            st.warning(f"{policy['guidelines']}")
        else:
            response = requests.post(API_URL, json={
                "username": username,
                "email": email,
                "password": password
            })

            if response.status_code == 200:
                st.success("User registered successfully!")
                st.session_state.page = "login"
                st.rerun()
            else:
                st.error(f"Error: {response.json().get('detail')}")


    if st.button("Back to login"):
        st.session_state.page = "login"
        st.rerun()
