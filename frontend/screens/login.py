import streamlit as st
import requests
import time
import re

LOGIN_API_URL = "http://backend:8000/login"
RESET_PASSWORD_URL = "http://backend:8000/request-password-reset"
policy = requests.get("http://backend:8000/password-policy").json()

def show():
    st.title("Comunication LTD")
    st.subheader("Login")

    # Input fields for login
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):

        if not username or not password:
            st.warning("All fields are required.")
            
        else:
    
            # Send login request to backend
            response = requests.post(LOGIN_API_URL, json={
                "username": username,
                "password": password
            })

            if response.status_code == 200:
                data = response.json()
                st.session_state["username"] = username

                # Redirect to password change screen if forced
                if data.get("force_password_change"):
                    st.info("Moved to pick a new password for your safety")
                    time.sleep(2)
                    st.session_state.page = "change_password"
                else:
                    st.success(data.get("message"))
                    time.sleep(2)
                    st.session_state.page = "system"

                st.rerun()
            else:
                # Safely extract “detail” if JSON, else show raw text
                try:
                    detail = response.json().get("detail")
                except ValueError:
                    detail = response.text or "Unknown error"
                st.error(f"Error: {detail}")

    st.markdown("---")

    # Navigate to register screen
    if st.button("Register"):
        st.session_state.page = "register"
        st.rerun()

    # Password reset section
    with st.expander("Forgot Password?"):
        email = st.text_input("Enter your email to reset password")
        if st.button("Send Reset Link"):
            if not email:
                st.warning("Please enter your email.")
            elif not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
                st.warning("Enter a valid email (e.g., name@example.com)")
            else:
                try:
                    response = requests.post(RESET_PASSWORD_URL, json={"email": email})
                    if response.status_code == 200:
                        data = response.json()
                        st.success(data.get("message"))
                        time.sleep(4)
                        st.session_state.page = "verify_token"
                        st.rerun()
                    else:
                        # Safely extract “detail” if JSON, else show raw text
                        try:
                            detail = response.json().get("detail")
                        except ValueError:
                            detail = response.text or "Unknown error"
                            st.error(f"Error: {detail}")
                except Exception as e:
                    st.error(f"Something went wrong: {e}")

