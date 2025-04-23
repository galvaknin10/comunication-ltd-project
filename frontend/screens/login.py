import streamlit as st
import requests
import time
import re

LOGIN_API_URL = "http://backend:8000/login"
RESET_PASWWORD_URL = "http://backend:8000/request-password-reset"
policy = requests.get("http://backend:8000/password-policy").json()

def show():
    st.title("Comunication LTD")
    st.subheader("Login")

    # Regular login form
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        response = requests.post(LOGIN_API_URL, json={
            "username": username,
            "password": password
        })

        if response.status_code == 200:
            data = response.json()

            st.session_state["username"] = username
        
            if data.get("force_password_change"):
                st.info("Moved to pick a new password for your safety")
                time.sleep(2)
                st.session_state.page = "change_password"
            else:
                st.success("Login successful!")
                time.sleep(2)
                st.session_state.page = "system"

            st.rerun()
        else:
            st.error(f"Error: {response.json().get('detail')}")



    st.markdown("---")

    # Register navigation
    if st.button("Register"):
        st.session_state.page = "register"
        st.rerun()

    with st.expander("Forgot Password?"):
        email = st.text_input("Enter your email to reset password")
        if st.button("Send Reset Link"):
            if not email:
                st.warning("Please enter your email.")
            elif not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
                st.warning("Enter a valid email (e.g., name@example.com)")
            else:
                try:
                    response = requests.post(RESET_PASWWORD_URL, json={"email": email})
                    if response.status_code == 200:
                        username = response.json().get("username")
                        st.success("Reset token generated! (Check your email)")
                        time.sleep(2)
                        st.session_state["username"] = username
                        st.session_state.page = "verify_token" 
                        st.rerun()
                    else:
                        st.error(f"Error: {response.json().get('detail')}")
                except Exception as e:
                    st.error(f"Something went wrong: {e}")

