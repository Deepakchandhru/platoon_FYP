import grpc
from concurrent import futures
import platoon_pb2
import platoon_pb2_grpc
import asyncpg
import asyncio
import requests
from web3 import Web3
from solcx import compile_source, set_solc_version

NODE_URL = "http://localhost:4000"

DB_CONFIG = {
    "user": "postgres",
    "password": "5112",
    "database": "avplatoon",
    "host": "localhost",
    "port": 5432
}

# Blockchain setup
set_solc_version("0.8.17")
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
if not w3.is_connected():
    raise ConnectionError("Unable to connect to blockchain provider")

# Load and compile contract
def load_contract_source():
    with open("MerkleCommitment.sol", "r", encoding="utf-8") as f:
        return f.read()

def compile_contract(source):
    compiled = compile_source(source)
    _, contract_interface = compiled.popitem()
    return contract_interface['abi'], contract_interface['bin']

source = load_contract_source()
abi, bytecode = compile_contract(source)

# Deploy contract (run once, or set address)
def deploy_contract():
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Contract.constructor().transact({"from": w3.eth.accounts[0], "gas": 3000000})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.contractAddress

contract_address = deploy_contract()  # Or set to existing address
contract = w3.eth.contract(address=contract_address, abi=abi)

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

def insert_commitment_blockchain(commitment):
    tx_hash = contract.functions.addCommitment(Web3.to_bytes(int(commitment)), 80, 80).transact({"from": w3.eth.accounts[0]})
    w3.eth.wait_for_transaction_receipt(tx_hash)

def get_commitments_blockchain():
    commitments = contract.functions.getCommitments().call()
    return [str(int.from_bytes(c, 'big')) for c in commitments]

def get_vehicle_data(commitment):
    cap, trust = contract.functions.getVehicleData(Web3.to_bytes(int(commitment))).call()
    return cap, trust

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
    print({
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
        insert_commitment_blockchain(commitment)

        return platoon_pb2.RegisterResponse(
            status="REGISTERED",
            commitment=str(commitment)
        )

    def AuthVehicle(self, request, context):
        all_commitments = get_commitments_blockchain()
        commitment = str(request.commitment)

        if commitment not in all_commitments:
            return platoon_pb2.AuthResponse(status="REJECTED")

        capability_score, trust_token = get_vehicle_data(commitment)
        merkle = build_merkle(commitment, all_commitments)

        zkp_input = {
            "vehicle_secret": request.vehicle_secret,
            "manufacturer_signature": request.manufacturer_signature,
            "pathElements": merkle["pathElements"],
            "pathIndices": merkle["pathIndices"],
            "merkle_root": merkle["merkle_root"],
            "capability_score": capability_score,
            "trust_token": trust_token,
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
    print("gRPC server running on port 50051")
