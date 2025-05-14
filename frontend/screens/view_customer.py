import streamlit as st
import requests

def show():
    st.title("🧾 Customer Details")

    # Get the last added customer ID from session
    customer_id = st.session_state.get("customer_id")

    try:
        # Fetch customer details from backend
        response = requests.get(f"http://backend:8000/get-customer/{customer_id}")
        if response.status_code == 200:
            customer = response.json()
            
            # Display customer info (XSS can occur here if output is not sanitized server-side)
            st.markdown(f"**Name:** {customer['name']}", unsafe_allow_html=True)
            st.text(f"Email: {customer['email']}")
            st.text(f"Phone: {customer['phone']}")
        else:
            try:
                st.error(f"Error: {response.json().get('detail', 'Unknown error')}")
            except:
                detail = response.text or "Unknown error"
                st.error(f"Error: {detail}")
    except Exception as e:
        st.error(f"Something went wrong: {e}")

    # Navigation: return to system dashboard
    if st.button("Go Back"):
        st.session_state.page = "system"
        st.rerun()
