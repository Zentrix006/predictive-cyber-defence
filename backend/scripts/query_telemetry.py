import asyncio
import httpx
from datetime import timedelta
from app.core.security import create_access_token

async def main():
    # 1. Generate an admin token directly using the backend's security module
    token = create_access_token(
        subject="00000000-0000-0000-0000-000000000000", 
        additional_claims={"roles": ["admin"]}
    )
    
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    # 2. Query the live telemetry endpoint
    print("[*] Querying /api/v1/network/live-telemetry...")
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        response = await client.get("/api/v1/network/live-telemetry?limit=5", headers=headers)
        
        if response.status_code != 200:
            print(f"[!] API Error: {response.status_code}")
            print(response.text)
            return
            
        data = response.json()
        
        print("\n=== AI Telemetry Analysis ===")
        print(f"Available: {data.get('available')}")
        print(f"Total Records Parsed: {len(data.get('records', []))}")
        
        for idx, record in enumerate(data.get('records', [])):
            print(f"\n--- Anomaly Record {idx+1} ---")
            raw = record.get('raw', {})
            norm = record.get('normalized_flow', {})
            print(f"Source IP:   {norm.get('src_ip')} (Port: {norm.get('src_port')})")
            print(f"Target IP:   {norm.get('dst_ip')} (Port: {norm.get('dst_port')})")
            print(f"State:       {raw.get('conn_state')} (Rejected)")
            print(f"Features:    {record.get('feature_vector', [0,0,0,0,0])[:5]}... (35-dimensional vector generated)")

if __name__ == "__main__":
    asyncio.run(main())
