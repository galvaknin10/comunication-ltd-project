import streamlit as st
import requests
import pandas as pd

def show():
    st.title("🧾 Customer Details")

    if st.button("View Recent Customer"):
        resp = requests.get(f"http://backend:8000/get-customer/{st.session_state.customer_id}")
        if resp.ok:
            cust = resp.json()
            df = pd.DataFrame([cust])
            # turn DF into an HTML table without escaping
            html = df.to_html(escape=False, index=False)
            # render that HTML
            st.markdown(html, unsafe_allow_html=True)
        else:
            st.error(resp.json().get("detail", resp.text))

    if st.button("View All Customers"):
        resp = requests.get("http://backend:8000/get-customers")
        if resp.ok:
            df = pd.DataFrame(resp.json())
            html = df.to_html(escape=False, index=False)
            st.markdown(html, unsafe_allow_html=True)
        else:
            st.error(resp.json().get("detail", resp.text))

    if st.button("Go Back"):
        st.session_state.page = "system"
        st.rerun()
