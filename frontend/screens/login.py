import streamlit as st
import requests

def show():
    st.title("🔐 Comunication LTD")
    st.subheader("Login")

    # Regular login form
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        # TODO: Validate login with backend
        st.success("Logged in successfully")
        st.session_state.page = "system"

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
