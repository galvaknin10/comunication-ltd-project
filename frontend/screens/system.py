import streamlit as st
import requests
import re
import time

API_URL = "http://backend:8000/customers"

def show():
    st.title("📋 System Dashboard")
    st.subheader("Insert New Customer")

    # Input fields for customer details
    customer_id = st.text_input("Customer ID")
    full_name = st.text_input("Full Name")
    email = st.text_input("Email")
    phone = st.text_input("Phone Number")

    if st.button("Add Customer"):
        # 1. Validate that all fields are filled
        if not customer_id or not full_name or not email or not phone:
            st.warning("All fields are required.")
            return

        # Turn this off to demonstrate sqli attack
        # 2. Validate customer ID (e.g., Israeli ID - 9 digits)
        # if not re.fullmatch(r"\d{9}", customer_id):
        #     st.warning("Customer ID must be exactly 9 digits.")
        #     return

        # 3. Basic email format validation
        if not re.fullmatch(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
            st.warning("Enter a valid email (e.g., name@example.com).")
            return

        # 4. Phone number format validation (e.g., 052-1234567)
        if not re.fullmatch(r"\d{3}-\d{7}", phone):
            st.warning("Phone must be in the format ###-#######.")
            return

        # 5. Submit data to backend
        try:
            response = requests.post(API_URL, json={
                "customer_id": customer_id,
                "name": full_name,
                "email": email,
                "phone": phone
            })

            if response.status_code == 200:
                customer = response.json()
                st.success(f"Customer '{customer['customer_name']}' added successfully!")
                time.sleep(2)
                st.session_state["customer_id"] = customer_id
                st.session_state.page = "view_customer"
                st.rerun()
            else:
                try:
                    detail = response.json().get("detail")
                    if isinstance(detail, list):
                        st.error(f"Error: {detail[0].get('msg', 'Unknown error')}")
                    else:
                        st.error(f"Error: {detail}")
                except:
                    st.error("Error: Server did not return valid JSON.")
        except Exception as e:
            st.error(f"Something went wrong: {e}")

    # Logout button
    if st.button("Logout"):
        st.session_state.page = "login"
        st.rerun()
