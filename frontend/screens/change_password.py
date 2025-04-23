import streamlit as st
import requests
import re
from screens.login import policy
import time

CHANGE_PASSWORD_URL = "http://backend:8000/change-password"

def show():
    st.title("🔐 Change Password")
    st.markdown(f"""
    **Password requirements:**
    - Minimum **{policy['min_length']}** characters  
    - {policy['guidelines']}
    """)

    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Update Password"):
        if not new_password or not confirm_password:
            st.warning("Please fill in all fields.")
        elif new_password != confirm_password:
            st.warning("Passwords do not match.")
        elif len(new_password) < policy["min_length"]:
            st.warning(f"Password must be at least {policy['min_length']} characters long.")
        elif not re.match(policy["regex"], new_password):
            st.warning(f"{policy['guidelines']}")
        else:
            try:
                response = requests.post(CHANGE_PASSWORD_URL, json={
                    "username": st.session_state.get("username"),
                    "new_password": new_password
                })

                if response.status_code == 200:
                    st.success("Password changed successfully. Please log in again.")
                    time.sleep(2)
                    st.session_state.page = "login"
                    st.rerun()
                else:
                    st.error(f"Error: {response.json().get('detail')}")
            except Exception as e:
                st.error(f"Something went wrong: {e}")
