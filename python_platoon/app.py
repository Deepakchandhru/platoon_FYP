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
    return [str(r["commitment"]) for r in rows]

def build_merkle(commitment, leaves):
    idx = leaves.index(commitment)

    if idx % 2 == 0:
        left = leaves[idx]
        right = leaves[idx + 1] if idx + 1 < len(leaves) else "0"
        sibling = right
        path_index = 0
    else:
        left = leaves[idx - 1]
        right = leaves[idx]
        sibling = left
        path_index = 1

    resp = requests.post(
        f"{NODE_URL}/zkp/hash-pair",
        json={"a": left, "b": right}
    )

    root = str(resp.json()["hash"])

    print({
        "pathElements": [sibling],
        "pathIndices": [path_index],
        "merkle_root": root
    })
    print(resp.json())

    return {
        "pathElements": [sibling],
        "pathIndices": [path_index],
        "merkle_root": root
    }


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
        "status": "REGISTERED"
    })


@app.route("/vehicle/auth", methods=["POST"])
def auth():
    data = request.json

    all_commitments = asyncio.run(get_commitments())

    resp = requests.post(
        f"{NODE_URL}/zkp/commitment",
        json=data
    )
    commitment = resp.json()["commitment"]

    if commitment not in all_commitments:
        return jsonify({"status": "REJECTED"}), 403

    merkle = build_merkle(commitment, all_commitments)

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
