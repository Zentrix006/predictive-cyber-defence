#!/usr/bin/env bash
set -euo pipefail

DEST_DIR="/home/zentrix/Desktop/SIH/predictive-cyber-defence/ml-engine/data/raw/cse-cic-ids2018"
mkdir -p "$DEST_DIR"
cd "$DEST_DIR"

declare -A EXPECTED_SIZES=(
    ["Wednesday-14-02-2018"]=358223333
    ["Thursday-15-02-2018"]=375945899
    ["Friday-16-02-2018"]=333723605
    ["Thuesday-20-02-2018"]=4054925350
    ["Wednesday-21-02-2018"]=328893673
    ["Thursday-22-02-2018"]=382636202
    ["Friday-23-02-2018"]=382840456
    ["Wednesday-28-02-2018"]=209249758
    ["Thursday-01-03-2018"]=107842858
    ["Friday-02-03-2018"]=352368373
)

FILES=(
    "Wednesday-14-02-2018"
    "Thursday-15-02-2018"
    "Friday-16-02-2018"
    "Thuesday-20-02-2018"
    "Wednesday-21-02-2018"
    "Thursday-22-02-2018"
    "Friday-23-02-2018"
    "Wednesday-28-02-2018"
    "Thursday-01-03-2018"
    "Friday-02-03-2018"
)

BASE_URL="https://cse-cic-ids2018.s3.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms"

echo "=== CSE-CIC-IDS2018 Dataset Verification & Download ==="
echo "Target directory: $DEST_DIR"

for f in "${FILES[@]}"; do
    FILENAME="${f}_TrafficForML_CICFlowMeter.csv"
    EXPECTED="${EXPECTED_SIZES[$f]}"
    URL="${BASE_URL}/${FILENAME}"

    # Check if a background curl is currently writing to this file
    if pgrep -f "curl.*${FILENAME}" >/dev/null 2>&1; then
        echo "[IN PROGRESS] $FILENAME is currently being downloaded by another process. Waiting for completion..."
        while pgrep -f "curl.*${FILENAME}" >/dev/null 2>&1; do
            CURRENT_SIZE=$(stat -c%s "$FILENAME" 2>/dev/null || echo 0)
            PERCENT=$(( CURRENT_SIZE * 100 / EXPECTED ))
            echo "  -> Downloading: ${CURRENT_SIZE} / ${EXPECTED} bytes (${PERCENT}%)"
            sleep 10
        done
        echo "[DONE] Download process for $FILENAME finished."
    fi

    # Check existing file size
    if [[ -f "$FILENAME" ]]; then
        ACTUAL=$(stat -c%s "$FILENAME")
        if [[ "$ACTUAL" -eq "$EXPECTED" ]]; then
            echo "[OK] $FILENAME already present and verified ($ACTUAL bytes)."
            continue
        else
            echo "[PARTIAL] $FILENAME present with $ACTUAL bytes (expected $EXPECTED). Resuming download..."
        fi
    else
        echo "[MISSING] $FILENAME. Starting download..."
    fi

    curl -fL --retry 5 --retry-delay 2 -C - -o "$FILENAME" "$URL"

    ACTUAL=$(stat -c%s "$FILENAME")
    if [[ "$ACTUAL" -ne "$EXPECTED" ]]; then
        echo "[ERROR] $FILENAME size mismatch: got $ACTUAL, expected $EXPECTED"
        exit 1
    fi
    echo "[VERIFIED] $FILENAME downloaded and verified ($ACTUAL bytes)."
done

echo "=== All 10 CSE-CIC-IDS2018 files successfully verified! ==="
