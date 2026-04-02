import grpc
from concurrent import futures
import platoon_pb2
import platoon_pb2_grpc
import asyncpg
import asyncio
import requests
import uuid
import time
import queue
import threading
from google.protobuf.timestamp_pb2 import Timestamp
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
    with open("cats.sol", "r", encoding="utf-8") as f:
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

PLATOONS = {}

AUTHENTICATED_VEHICLES = set()

EVENT_SUBSCRIBERS = []
SUBSCRIBERS_LOCK = threading.Lock()

def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

def now_timestamp() -> Timestamp:
    ts = Timestamp()
    s = int(time.time())
    ts.seconds = s
    ts.nanos = int((time.time() - s) * 1e9)
    return ts

def insert_commitment_blockchain(commitment):
    tx_hash = contract.functions.addCommitment(Web3.to_bytes(int(commitment)), 80, 80).transact({"from": w3.eth.accounts[0]})
    w3.eth.wait_for_transaction_receipt(tx_hash)

def get_commitments_blockchain():
    commitments = contract.functions.getCommitments().call()
    return [str(int.from_bytes(c, 'big')) for c in commitments]

def get_vehicle_data(commitment):
    cap, trust = contract.functions.getVehicleData(Web3.to_bytes(int(commitment))).call()
    return cap, trust

# New blockchain functions for reputation, votes, flags
def update_reputation_blockchain(commitment, score, trust_state):
    """Update final reputation state on blockchain"""
    tx_hash = contract.functions.updateReputation(Web3.to_bytes(int(commitment)), score, trust_state).transact({"from": w3.eth.accounts[0]})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.transactionHash.hex()

def get_reputation_blockchain(commitment):
    score, trust_state, last_updated = contract.functions.getReputation(Web3.to_bytes(int(commitment))).call()
    return score, trust_state, last_updated

def record_vote_blockchain(target_commitment, vote_type, reason):
    """Record a vote on blockchain"""
    tx_hash = contract.functions.recordVote(Web3.to_bytes(int(target_commitment)), vote_type, reason).transact({"from": w3.eth.accounts[0]})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.transactionHash.hex()

def get_vote_count_blockchain():
    return contract.functions.getVoteCount().call()

def get_vote_blockchain(index):
    voter, target, vote_type, timestamp, reason = contract.functions.getVote(index).call()
    return voter, str(int.from_bytes(target, 'big')), vote_type, timestamp, reason

def add_flag_blockchain(vehicle_commitment, flag_type, window_id):
    """Add flag anchor on blockchain (optional)"""
    tx_hash = contract.functions.addFlag(Web3.to_bytes(int(vehicle_commitment)), flag_type, window_id).transact({"from": w3.eth.accounts[0]})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.transactionHash.hex()

def get_flag_count_blockchain():
    return contract.functions.getFlagCount().call()

def get_flag_blockchain(index):
    vehicle, flag_type, window_id, timestamp = contract.functions.getFlag(index).call()
    return str(int.from_bytes(vehicle, 'big')), flag_type, window_id, timestamp

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

async def commitment_exists(commitment):
    conn = await get_conn()
    row = await conn.fetchrow(
        "SELECT commitment FROM authorized_vehicles WHERE commitment = $1",
        commitment
    )
    await conn.close()
    return row is not None

# New PostgreSQL functions for reputation system
async def init_vehicle_reputation(vehicle_id: str, initial_score: int = 0):
    conn = await get_conn()
    await conn.execute("""
        INSERT INTO reputation (vehicle_id, score, trust_state, created_at, last_updated)
        VALUES ($1, $2, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (vehicle_id) DO NOTHING
    """, vehicle_id, initial_score)
    await conn.close()

async def get_vehicle_reputation(vehicle_id: str):
    conn = await get_conn()
    row = await conn.fetchrow("""
        SELECT vehicle_id, score, trust_state, last_updated, created_at, blockchain_tx_hash
        FROM reputation WHERE vehicle_id = $1
    """, vehicle_id)
    await conn.close()
    return dict(row) if row else None

async def update_vehicle_reputation(vehicle_id: str, new_score: int, new_trust_state: int, blockchain_tx_hash: str = None):
    conn = await get_conn()
    await conn.execute("""
        UPDATE reputation 
        SET score = $2, trust_state = $3, last_updated = CURRENT_TIMESTAMP, blockchain_tx_hash = $4
        WHERE vehicle_id = $1
    """, vehicle_id, new_score, new_trust_state, blockchain_tx_hash)
    await conn.close()

async def record_vote_history(voter_id: str, target_id: str, vote_type: str):
    conn = await get_conn()
    await conn.execute("""
        INSERT INTO vote_history (voter_id, target_id, vote_type, timestamp)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
    """, voter_id, target_id, vote_type)
    await conn.close()

async def get_recent_vote_history(voter_id: str, time_window_seconds: float):
    conn = await get_conn()
    rows = await conn.fetch("""
        SELECT voter_id, target_id, vote_type, timestamp
        FROM vote_history 
        WHERE voter_id = $1 AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '%s seconds')
        ORDER BY timestamp DESC
    """ % time_window_seconds, voter_id)
    await conn.close()
    return [dict(row) for row in rows]

async def add_flag(vehicle_id: str, flag_type: str, window_id: int, blockchain_tx_hash: str = None):
    conn = await get_conn()
    await conn.execute("""
        INSERT INTO flags (vehicle_id, flag_type, window_id, timestamp, blockchain_tx_hash)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4)
    """, vehicle_id, flag_type, window_id, blockchain_tx_hash)
    await conn.close()

async def get_active_flags(vehicle_id: str):
    conn = await get_conn()
    rows = await conn.fetch("""
        SELECT id, vehicle_id, flag_type, window_id, timestamp, blockchain_tx_hash
        FROM flags 
        WHERE vehicle_id = $1 AND expired = FALSE
        ORDER BY timestamp DESC
    """, vehicle_id)
    await conn.close()
    return [dict(row) for row in rows]

async def record_broadcast_message(sender_id: str, msg_type: str, sequence_num: int, raw_json: str):
    conn = await get_conn()
    await conn.execute("""
        INSERT INTO broadcast_messages (sender_id, msg_type, timestamp, sequence_num, raw_json)
        VALUES ($1, $2, CURRENT_TIMESTAMP, $3, $4)
    """, sender_id, msg_type, sequence_num, raw_json)
    await conn.close()

async def get_all_reputations():
    conn = await get_conn()
    rows = await conn.fetch("""
        SELECT vehicle_id, score, trust_state, last_updated, created_at, blockchain_tx_hash
        FROM reputation ORDER BY score DESC
    """)
    await conn.close()
    return [dict(row) for row in rows]


def build_merkle(commitment, all_commitments):
    """Build Merkle proof for depth=1 tree."""
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

    return {
        "pathElements": [str(sibling)],
        "pathIndices": [path_index],
        "merkle_root": root
    }


def broadcast_event(event):
    """Add event to all subscriber queues."""
    with SUBSCRIBERS_LOCK:
        for q in EVENT_SUBSCRIBERS:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass

def create_platoon_event(event_type, pid, actor_id, message="", target_pid="", platoon=None):
    """Create a PlatoonEvent protobuf message."""
    event = platoon_pb2.PlatoonEvent()
    event.type = event_type
    event.pid = pid or ""
    event.actor_id = actor_id or ""
    event.message = message
    event.target_pid = target_pid or ""
    event.ts.CopyFrom(now_timestamp())
    
    if platoon:
        event.platoon.CopyFrom(platoon)
    
    return event

def platoon_to_proto(pid):
    if pid not in PLATOONS:
        return None
    
    p = PLATOONS[pid]
    platoon = platoon_pb2.Platoon()
    platoon.pid = pid
    platoon.speed = p.get("speed", 60.0)
    
    created_ts = Timestamp()
    created_ts.seconds = int(p["created_at"])
    platoon.created_at.CopyFrom(created_ts)
    
    for m in p["members"]:
        member = platoon_pb2.PlatoonMember()
        member.commitment = m["commitment"]
        member.is_leader = m["is_leader"]
        member.position = m["position"]
        
        joined_ts = Timestamp()
        joined_ts.seconds = int(m["joined_at"])
        member.joined_at.CopyFrom(joined_ts)
        
        platoon.members.append(member)
    
    return platoon

def get_vehicle_platoon(commitment):
    """Find which platoon a vehicle is in. Returns (pid, member_data, index) or (None, None, None)."""
    for pid, p_data in PLATOONS.items():
        for idx, m in enumerate(p_data["members"]):
            if m["commitment"] == commitment:
                return pid, m, idx
    return None, None, None

class PlatoonService(platoon_pb2_grpc.PlatoonServiceServicer):

    def RegisterVehicle(self, request, context):
        """
        Register a vehicle by computing Poseidon commitment.
        Secrets are NOT stored - only the commitment.
        """
        vehicle_secret = request.vehicle_secret
        manufacturer_signature = request.manufacturer_signature

        if not vehicle_secret or not manufacturer_signature:
            return platoon_pb2.RegisterResponse(
                status="ERROR",
                commitment=""
            )

        # Check if already registered with same secrets
        resp = requests.post(
            f"{NODE_URL}/zkp/commitment",
            json={
                "vehicle_secret": vehicle_secret,
                "manufacturer_signature": manufacturer_signature
            }
        )

        if resp.status_code != 200:
            return platoon_pb2.RegisterResponse(
                status="ERROR",
                commitment=""
            )

        commitment = str(resp.json()["commitment"])

        # Check if commitment already exists
        if commitment in get_commitments_blockchain():
            return platoon_pb2.RegisterResponse(
                status="ALREADY_REGISTERED",
                commitment=commitment
            )

        # Store commitment in blockchain
        insert_commitment_blockchain(commitment)

        event = create_platoon_event(
            platoon_pb2.PlatoonEvent.VEHICLE_REGISTERED,
            "",
            commitment,
            f"Vehicle {commitment[:16]}... registered"
        )
        broadcast_event(event)

        return platoon_pb2.RegisterResponse(
            status="REGISTERED",
            commitment=commitment
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
            "capability_threshold": 50,
            "trust_threshold": 50
        }

        resp = requests.post(
            f"{NODE_URL}/zkp/verify-vehicle",
            json=zkp_input
        )

        status = resp.json().get("status", "REJECTED")

        if status == "APPROVED":
            AUTHENTICATED_VEHICLES.add(commitment)

        return platoon_pb2.AuthResponse(status=status)

    def JoinPlatoon(self, request, context):
        commitment = request.commitment
        pid = request.pid

        if not commitment:
            return platoon_pb2.JoinResponse(
                ok=False,
                pid="",
                message="Empty commitment"
            )

        if commitment not in AUTHENTICATED_VEHICLES:
            return platoon_pb2.JoinResponse(
                ok=False,
                pid="",
                message="Vehicle not authenticated. Call AuthVehicle first."
            )

        existing_pid, _, _ = get_vehicle_platoon(commitment)
        if existing_pid:
            return platoon_pb2.JoinResponse(
                ok=False,
                pid=existing_pid,
                message=f"Already in platoon {existing_pid}. Leave first to join another."
            )

        now = time.time()

        if not pid:
            pid = "p-" + uuid.uuid4().hex[:8]
            PLATOONS[pid] = {
                "created_at": now,
                "speed": 60.0,
                "members": [{
                    "commitment": commitment,
                    "is_leader": True,
                    "position": 0,
                    "joined_at": now
                }]
            }
            message = f"Created new platoon {pid} as leader"
        else:
            if pid not in PLATOONS:
                return platoon_pb2.JoinResponse(
                    ok=False,
                    pid="",
                    message=f"Platoon {pid} not found"
                )

            position = len(PLATOONS[pid]["members"])
            PLATOONS[pid]["members"].append({
                "commitment": commitment,
                "is_leader": False,
                "position": position,
                "joined_at": now
            })
            message = f"Joined platoon {pid} at position {position}"

        event = create_platoon_event(
            platoon_pb2.PlatoonEvent.PLATOON_JOINED,
            pid,
            commitment,
            message,
            platoon=platoon_to_proto(pid)
        )
        broadcast_event(event)

        return platoon_pb2.JoinResponse(ok=True, pid=pid, message=message)

    def LeavePlatoon(self, request, context):
        commitment = request.commitment

        if not commitment:
            return platoon_pb2.LeaveResponse(
                ok=False,
                message="Empty commitment"
            )

        # Find which platoon the vehicle is in
        found_pid, member_data, found_idx = get_vehicle_platoon(commitment)

        if not found_pid:
            return platoon_pb2.LeaveResponse(
                ok=False,
                message="Vehicle not in any platoon"
            )

        was_leader = member_data["is_leader"]
        my_pos = member_data["position"]
        members = PLATOONS[found_pid]["members"]

        # Check if tail (simple removal)
        if my_pos == len(members) - 1:
            # Remove tail member
            members.pop(found_idx)

            if len(members) == 0:
                # Platoon dissolved
                del PLATOONS[found_pid]
                event = create_platoon_event(
                    platoon_pb2.PlatoonEvent.PLATOON_LEFT,
                    found_pid,
                    commitment,
                    f"Left and dissolved platoon {found_pid}"
                )
                broadcast_event(event)
                return platoon_pb2.LeaveResponse(ok=True, message=f"Left and dissolved platoon {found_pid}")

            # Reassign leader if needed
            if was_leader and len(members) > 0:
                members[0]["is_leader"] = True

            event = create_platoon_event(
                platoon_pb2.PlatoonEvent.PLATOON_LEFT,
                found_pid,
                commitment,
                f"Left platoon {found_pid} (tail)",
                platoon=platoon_to_proto(found_pid)
            )
            broadcast_event(event)
            return platoon_pb2.LeaveResponse(ok=True, message=f"Left platoon {found_pid}")

        members.pop(found_idx)

        for i, m in enumerate(members):
            m["position"] = i

        if was_leader and len(members) > 0:
            members[0]["is_leader"] = True

        event = create_platoon_event(
            platoon_pb2.PlatoonEvent.PLATOON_LEFT,
            found_pid,
            commitment,
            f"Left platoon {found_pid} (split->merge)",
            platoon=platoon_to_proto(found_pid)
        )
        broadcast_event(event)

        return platoon_pb2.LeaveResponse(ok=True, message=f"Left platoon {found_pid}")

    def MergePlatoon(self, request, context):
        commitment = request.commitment
        src_pid = request.src_pid
        dst_pid = request.dst_pid

        if not commitment or not src_pid or not dst_pid:
            return platoon_pb2.MergeResponse(
                ok=False,
                dst_pid="",
                message="Missing required fields"
            )

        if src_pid == dst_pid:
            return platoon_pb2.MergeResponse(
                ok=False,
                dst_pid="",
                message="Source and destination cannot be the same"
            )

        if src_pid not in PLATOONS:
            return platoon_pb2.MergeResponse(
                ok=False,
                dst_pid="",
                message=f"Source platoon {src_pid} not found"
            )

        if dst_pid not in PLATOONS:
            return platoon_pb2.MergeResponse(
                ok=False,
                dst_pid="",
                message=f"Destination platoon {dst_pid} not found"
            )

        src_leader = None
        for m in PLATOONS[src_pid]["members"]:
            if m["is_leader"]:
                src_leader = m["commitment"]
                break

        if src_leader != commitment:
            return platoon_pb2.MergeResponse(
                ok=False,
                dst_pid="",
                message="Only source platoon leader can initiate merge"
            )

        base_position = len(PLATOONS[dst_pid]["members"])
        for i, m in enumerate(PLATOONS[src_pid]["members"]):
            PLATOONS[dst_pid]["members"].append({
                "commitment": m["commitment"],
                "is_leader": False,
                "position": base_position + i,
                "joined_at": m["joined_at"]
            })

        del PLATOONS[src_pid]

        event = create_platoon_event(
            platoon_pb2.PlatoonEvent.PLATOON_MERGED,
            dst_pid,
            commitment,
            f"Merged {src_pid} into {dst_pid}",
            target_pid=src_pid,
            platoon=platoon_to_proto(dst_pid)
        )
        broadcast_event(event)

        return platoon_pb2.MergeResponse(
            ok=True,
            dst_pid=dst_pid,
            message=f"Merged {src_pid} into {dst_pid}"
        )

    def ListPlatoons(self, request, context):
        response = platoon_pb2.PlatoonList()
        for pid in PLATOONS:
            platoon = platoon_to_proto(pid)
            if platoon:
                response.platoons.append(platoon)
        return response

    def WatchPlatoons(self, request, context):
        q = queue.Queue(maxsize=200)
        
        with SUBSCRIBERS_LOCK:
            EVENT_SUBSCRIBERS.append(q)

        filter_pids = set(request.pids) if request.pids else None

        try:
            while context.is_active():
                try:
                    event = q.get(timeout=1.0)
                   
                    if filter_pids:
                        if event.pid in filter_pids or event.target_pid in filter_pids:
                            yield event
                    else:
                        yield event
                except queue.Empty:
                    continue
        finally:
            with SUBSCRIBERS_LOCK:
                if q in EVENT_SUBSCRIBERS:
                    EVENT_SUBSCRIBERS.remove(q)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    platoon_pb2_grpc.add_PlatoonServiceServicer_to_server(
        PlatoonService(), server
    )
    server.add_insecure_port("[::]:50051")
    server.start()
    print("=" * 50)
    print("gRPC Platoon Server (ZKP Auth) running on port 50051")
    print("=" * 50)
    print("Endpoints:")
    print("  - RegisterVehicle: Register with (secret, signature)")
    print("  - AuthVehicle: ZKP-based authentication")
    print("  - JoinPlatoon: Join/create platoon")
    print("  - LeavePlatoon: Leave current platoon")
    print("  - MergePlatoon: Merge two platoons")
    print("  - ListPlatoons: List all platoons")
    print("  - WatchPlatoons: Stream events")
    print("=" * 50)
    server.wait_for_termination()

if __name__ == "__main__":
    serve()