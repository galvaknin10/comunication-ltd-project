import streamlit as st
import requests
import time

API_URL = "http://backend:8000/verify-token"

def show():
    st.title("🔐 Verify Reset Token")

    # Token input field
    token = st.text_input("Enter the token sent to your email. It expires in 3 minutes.")

    if st.button("Verify"):

        if not token:
            st.warning("This field is required.")
            return
        
        # Attempt to verify the reset token
        try:
            response = requests.post(API_URL, json={
                "token": token
            })

            if response.status_code == 200:
                data = response.json()
                st.success(data.get("message"))
                st.session_state["username"] = data.get("user_name")
                time.sleep(2)
                st.session_state.page = "change_password"
                st.rerun()

            else:
                try: # Handle known token validation errors
                    detail = response.json().get("detail")
                    if detail == "Reset token expired":
                        st.warning(f"{detail}, Please try again")
                        time.sleep(2)
                        st.session_state.page = "login"
                    elif detail == "Invalid token":
                        st.warning(f"{detail}, Please try again.")
                    else:
                        st.error(f"Error: {detail}")
                except ValueError:
                    detail = response.text or "Unknown error"
                    st.error(f"Error: {detail}")

        except Exception as e:
            st.error(f"Something went wrong: {e}")


    # Navigation: back to login screen
    if st.button("Back to login"):
        st.session_state.page = "login"
        st.rerun()

