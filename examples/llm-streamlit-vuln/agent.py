import os

from langchain_openai import ChatOpenAI

from retriever import search

llm = ChatOpenAI(model="gpt-4o-mini", api_key=os.getenv("OPENAI_API_KEY"))


def answer_question(state: dict) -> dict:
    docs = search(state["question"])
    prompt = f"Use these notes:\n{docs}\n\nQuestion: {state['question']}"
    response = llm.invoke(prompt)
    state["answer"] = response.content
    return summarize(state)


def summarize(state: dict) -> dict:
    answer = state["answer"]
    response = llm.invoke(f"Summarise in one line: {answer}")
    state["summary"] = response.content
    return state
