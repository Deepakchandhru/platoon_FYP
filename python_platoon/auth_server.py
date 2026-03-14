import grpc
from concurrent import futures
import platoon_pb2
import platoon_pb2_grpc
import asyncpg
import asyncio
import requests

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
    rows = await conn.fetch("SELECT commitment FROM authorized_vehicles ORDER BY id")
    await conn.close()
    return [str(r["commitment"]) for r in rows]

def build_merkle(commitment, all_commitments):
    idx = all_commitments.index(str(commitment))

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

    resp = requests.post(
        f"{NODE_URL}/zkp/hash-pair",
        json={"a": left, "b": right}
    )
    root = str(resp.json()["hash"])

    print(resp.json())
    print( {
        "pathElements": [str(sibling)],
        "pathIndices": [path_index],
        "merkle_root": root
    })

    return {
        "pathElements": [str(sibling)],
        "pathIndices": [path_index],
        "merkle_root": root
    }


class PlatoonService(platoon_pb2_grpc.PlatoonServiceServicer):

    def RegisterVehicle(self, request, context):
        data = {
            "vehicle_secret": request.vehicle_secret,
            "manufacturer_signature": request.manufacturer_signature
        }

        resp = requests.post(
            f"{NODE_URL}/zkp/commitment",
            json=data
        )

        commitment = resp.json()["commitment"]
        asyncio.run(insert_commitment(commitment))

        return platoon_pb2.RegisterResponse(
            status="REGISTERED",
            commitment=str(commitment)
        )

    def AuthVehicle(self, request, context):
        all_commitments = asyncio.run(get_commitments())
        commitment = str(request.commitment)

        if commitment not in all_commitments:
            return platoon_pb2.AuthResponse(status="REJECTED")

        merkle = build_merkle(commitment, all_commitments)

        zkp_input = {
            "vehicle_secret": request.vehicle_secret,
            "manufacturer_signature": request.manufacturer_signature,
            "pathElements": merkle["pathElements"],
            "pathIndices": merkle["pathIndices"],
            "merkle_root": merkle["merkle_root"],
            "capability_score": request.capability_score,
            "trust_token": request.trust_token,
            "capability_threshold": 60,
            "trust_threshold": 50
        }

        resp = requests.post(
            f"{NODE_URL}/zkp/verify-vehicle",
            json=zkp_input
        )

        return platoon_pb2.AuthResponse(
            status=resp.json().get("status", "REJECTED")
        )

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    platoon_pb2_grpc.add_PlatoonServiceServicer_to_server(
        PlatoonService(), server
    )
    server.add_insecure_port("[::]:50051")
    server.start()
    print("gRPC server running on port 50051")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
