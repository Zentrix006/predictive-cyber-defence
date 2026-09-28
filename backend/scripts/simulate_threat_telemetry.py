import json
import time
import os

TELEMETRY_DIR = "../ml-engine/dataset/telemetry-capture"
LOG_FILE = os.path.join(TELEMETRY_DIR, "99_synthetic_anomaly.log")

def generate_lateral_movement_anomaly():
    """Generates synthetic Zeek JSON logs mimicking an aggressive SSH/SMB scan."""
    print(f"Injecting synthetic lateral movement anomaly into {LOG_FILE}...")
    
    os.makedirs(TELEMETRY_DIR, exist_ok=True)
    
    attacker_ip = "172.20.20.100"
    target_subnet = "172.20.20."
    
    with open(LOG_FILE, "a") as f:
        # Simulate scanning 20 hosts on port 22 and 445 in 1 second
        for i in range(2, 22):
            # SSH attempt
            ssh_record = {
                "ts": time.time(),
                "uid": f"C{time.time_ns()}",
                "id.orig_h": attacker_ip,
                "id.orig_p": 45000 + i,
                "id.resp_h": f"{target_subnet}{i}",
                "id.resp_p": 22,
                "proto": "tcp",
                "duration": 0.1,
                "orig_bytes": 120,
                "resp_bytes": 0, # Unanswered / Rejected
                "conn_state": "REJ"
            }
            f.write(json.dumps(ssh_record) + "\n")
            
            # SMB attempt
            smb_record = {
                "ts": time.time(),
                "uid": f"C{time.time_ns()+1}",
                "id.orig_h": attacker_ip,
                "id.orig_p": 46000 + i,
                "id.resp_h": f"{target_subnet}{i}",
                "id.resp_p": 445,
                "proto": "tcp",
                "duration": 0.1,
                "orig_bytes": 120,
                "resp_bytes": 0,
                "conn_state": "REJ"
            }
            f.write(json.dumps(smb_record) + "\n")
            
    print(f"Successfully injected 40 anomalous flow records.")
    print("The backend ML worker and MultiSensorTelemetryNormalizer will parse these logs instantly.")

if __name__ == "__main__":
    generate_lateral_movement_anomaly()
