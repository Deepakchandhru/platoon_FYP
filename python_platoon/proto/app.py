from flask import Flask, request, jsonify
import asyncpg
import asyncio
import requests

app = Flask(__name__)

NODE_URL = "http://localhost:4000"

DB_CONFIG = {
    "user": "postgres",
    "password": "5112",
    "database": "avplatoon",
    "host": "localhost",
    "port": 5432
}

# ---------- DB HELPERS ----------

async def get_conn():
    return await asyncpg.connect(**DB_CONFIG)

async def insert_commitment(commitment):
    conn = await get_conn()
    await conn.execute(
        "INSERT INTO authorized_vehicles (commitment) VALUES ($1)",
        commitment
    )
    await conn.close()

async def get_commitments():
    conn = await get_conn()
    rows = await conn.fetch(
        "SELECT commitment FROM authorized_vehicles ORDER BY id"
    )
    await conn.close()
    # Normalize commitments to strings to avoid type mismatches
    return [str(r["commitment"]) for r in rows]

# ---------- MERKLE (DEPTH = 1) ----------

def build_merkle(commitment, all_commitments):
    # For depth=1 Merkle tree we always compute root = Poseidon(left, right).
    # Handle single-leaf tree by padding the right element with 0.
    # For depth=1 we form pairs (0,1), (2,3), ... and compute root = Poseidon(left,right)
    # Find index of the commitment and its sibling
    idx = None
    try:
        idx = all_commitments.index(str(commitment))
    except ValueError:
        # fallback: not found
        idx = 0

    if idx % 2 == 0:
        left = all_commitments[idx]
        right = all_commitments[idx + 1] if idx + 1 < len(all_commitments) else "0"
        path_index = 0
        sibling = right
    else:
        left = all_commitments[idx - 1]
        right = all_commitments[idx]
        path_index = 1
        sibling = left

    resp = requests.post(f"{NODE_URL}/zkp/hash-pair", json={"a": left, "b": right})
    root = str(resp.json()["hash"])

    return {
        "pathElements": [str(sibling)],
        "pathIndices": [path_index],
        "merkle_root": root
    }

# ---------- REGISTER ----------

@app.route("/vehicle/register", methods=["POST"])
def register():
    data = request.json

    resp = requests.post(
        f"{NODE_URL}/zkp/commitment",
        json=data
    )

    commitment = resp.json()["commitment"]

    asyncio.run(insert_commitment(commitment))

    return jsonify({
        "status": "REGISTERED",
        "commitment": commitment
    })

# ---------- AUTH ----------

@app.route("/vehicle/auth", methods=["POST"])
def auth():
    data = request.json

    all_commitments = asyncio.run(get_commitments())

    # Keep commitment as string to match DB-stored values
    commitment = str(data["commitment"])

    if commitment not in all_commitments:
        return jsonify({"status": "REJECTED"}), 403

    merkle = build_merkle(commitment, all_commitments)
    print("Merkle proof for commitment", commitment)
    print(merkle)

    zkp_input = {
        "vehicle_secret": data["vehicle_secret"],
        "manufacturer_signature": data["manufacturer_signature"],
        "pathElements": merkle["pathElements"],
        "pathIndices": merkle["pathIndices"],
        "merkle_root": merkle["merkle_root"],
        "capability_score": data["capability_score"],
        "trust_token": data["trust_token"],
        "capability_threshold": 60,
        "trust_threshold": 50
    }

    resp = requests.post(
        f"{NODE_URL}/zkp/verify-vehicle",
        json=zkp_input
    )

    return resp.json()

if __name__ == "__main__":
    app.run(port=5000, debug=True)
