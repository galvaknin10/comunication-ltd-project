import streamlit as st
import requests
import pandas as pd

def show():
    st.title("🧾 Customer Details")

    if st.button("View Recent Customer"):
        cid = st.session_state.get("customer_id")
        resp = requests.get(f"http://backend:8000/get-customer/{cid}")
        if resp.ok:
            cust = resp.json()
            st.table(pd.DataFrame([cust]))
        else:
            st.error(resp.json().get("detail", resp.text))

    if st.button("View All Customers"):
        resp = requests.get("http://backend:8000/get-customers")
        if resp.ok:
            all_custs = resp.json()  # list of dicts
            st.table(pd.DataFrame(all_custs))
        else:
            st.error(resp.json().get("detail", resp.text))

    if st.button("Go Back"):
        st.session_state.page = "system"
        st.rerun()
