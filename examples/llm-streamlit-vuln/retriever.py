import os

from qdrant_client import QdrantClient

client = QdrantClient(url=os.getenv("QDRANT_URL"), api_key=os.getenv("QDRANT_API_KEY"))


def search(text: str) -> list:
    return client.query_points(collection_name="kb", query=text, limit=3).points
