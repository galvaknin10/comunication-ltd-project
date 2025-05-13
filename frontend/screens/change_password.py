import streamlit as st
import requests
import re
from screens.login import policy
import time

CHANGE_PASSWORD_URL = "http://backend:8000/change-password"

def show():
    st.title("🔐 Change Password")
    
    # Display password policy details
    st.markdown(f"""
    **Password requirements:**
    - Minimum **{policy['min_length']}** characters  
    - {policy['guidelines']}
    """)

    # Input fields for validate old password, create new password and confirmation
    old_password = st.text_input("Old Password", type="password")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Update Password"):
        # Basic input validation
        if not new_password or not confirm_password or not old_password:
            st.warning("Please fill in all fields.")
        elif new_password != confirm_password:
            st.warning("Passwords do not match.")
        elif len(new_password) < policy["min_length"]:
            st.warning(f"Password must be at least {policy['min_length']} characters long.")
        elif not re.match(policy["regex"], new_password):
            st.warning(f"{policy['guidelines']}")
        else:
            # Submit password change request to backend
            try:
                response = requests.post(CHANGE_PASSWORD_URL, json={
                    "username": st.session_state.get("username"),
                    "old_password": old_password,
                    "new_password": new_password
                })

                if response.status_code == 200:
                    data = response.json()
                    st.success(f"{data.get('message')}, Please log in again.")
                    time.sleep(2)
                    st.session_state.page = "login"
                    st.rerun()
                else:
                    st.error(f"Error: {response.json().get('detail')}")
            except Exception as e:
                st.error(f"Something went wrong: {e}")

