import json
import os

from datasets import load_dataset
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

client = QdrantClient(url=os.getenv("QDRANT_URL"), api_key=os.getenv("QDRANT_API_KEY"))
model = SentenceTransformer("all-MiniLM-L6-v2")


def ingest() -> None:
    with open("kb.json") as f:
        docs = json.load(f)
    extra = load_dataset("some/dataset")
    client.upsert(collection_name="kb", points=[{"id": i, "vector": model.encode(d["text"]).tolist(),
                                                 "payload": d} for i, d in enumerate(docs)])
    return extra
