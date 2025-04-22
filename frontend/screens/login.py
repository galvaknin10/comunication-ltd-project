import streamlit as st
import requests


API_URL = "http://backend:8000/login"
policy = requests.get("http://backend:8000/password-policy").json()

def show():
    st.title("🔐 Comunication LTD")
    st.subheader("Login")

    # Regular login form
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        response = requests.post(API_URL, json={
            "username": username,
            "password": password
        })

        if response.status_code == 200:
            st.success("Login successful!")
            data = response.json()

            if data.get("force_password_change"):
                st.session_state.page = "change_password"
            else:
                st.session_state.page = "system"

            st.rerun()

        else:
            st.error(f"Error: {response.json().get('detail')}")


    st.markdown("---")

    # Register navigation
    if st.button("Register"):
        st.session_state.page = "register"
        st.rerun()

    # Forgot password flow
    with st.expander("Forgot Password?"):
        email = st.text_input("Enter your email to reset password")
        if st.button("Send Reset Link"):
            # TODO: Call backend to generate SHA-1 token and "send" it
            st.success("A reset token has been sent to your email.")
            st.session_state.page = "change_password"
