import streamlit as st
from screens import login, register, change_password, system

# Set Streamlit page config
st.set_page_config(page_title="Comunication LTD", layout="centered")

# Session state to track navigation
if "page" not in st.session_state:
    st.session_state.page = "login"

# Router
if st.session_state.page == "login":
    login.show()
elif st.session_state.page == "register":
    register.show()
elif st.session_state.page == "change_password":
    change_password.show()
elif st.session_state.page == "system":
    system.show()

