import streamlit as st
import requests
import time

API_URL = "http://backend:8000/verify-token"

def show():
    st.title("🔐 Verify Reset Token")

    # Token input field
    token = st.text_input("Enter the token sent to your email. It expires in 3 minutes.")

    if st.button("Verify"):
        username = st.session_state.get("username")

        # If no username in session, redirect to login
        if not username:
            st.error("Session expired. Please try again.")
            time.sleep(2)
            st.session_state.page = "login"
            st.rerun()

        # Attempt to verify the reset token
        try:
            response = requests.post(API_URL, json={
                "username": username,
                "token": token
            })

            if response.status_code == 200:
                st.success("Token verified!")
                time.sleep(2)
                st.session_state.page = "change_password"
                st.rerun()

            else:
                # Handle known token validation errors
                detail = response.json().get("detail")
                if detail == "Reset token expired":
                    st.warning("This token has expired. Please go back and request a new one.")
                    time.sleep(2)
                    st.session_state.page = "login"
                elif detail == "Invalid token":
                    st.warning("The token is incorrect. Please try again.")
                else:
                    st.error(f"Error: {detail}")

        except Exception as e:
            st.error(f"Something went wrong: {e}")


