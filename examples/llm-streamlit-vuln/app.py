"""Deliberately vulnerable Streamlit + LLM app (test fixture for the AI-app analyzer)."""
import streamlit as st

from agent import answer_question

st.title("Ask the knowledge base")
question = st.text_input("Your question")
if st.button("Ask"):
    try:
        result = answer_question({"question": question})
    except Exception as exc:
        st.error(f"Request failed: {exc}")
    else:
        st.markdown(result["answer"])
        st.caption(result["summary"])
