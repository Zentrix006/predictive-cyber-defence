"""Host-network passive identity service for Demo-2."""
from fastapi import FastAPI, Query
from app.services.network_identity import resolve_local_identity

app = FastAPI(title="Demo-2 LAN Identity Collector", docs_url=None, redoc_url=None)

@app.get("/lookup")
async def lookup(ip: str = Query(..., min_length=3, max_length=64)):
    return {"identity": resolve_local_identity(ip)}
