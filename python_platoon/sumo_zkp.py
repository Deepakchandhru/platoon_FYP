import os
import time
import math
import shutil
import threading
import queue
import re
import random
from typing import Dict, Optional, List, Tuple
import xml.etree.ElementTree as ET
from traci.exceptions import FatalTraCIError

try:
    import traci
except Exception:
    traci = None

grpc_client = None
platoon_ops = None
intra_ops = None
server_mod = None
sumo_ops = None
try:
    import client as grpc_client  
except Exception:
    grpc_client = None
try:
    import platoon_ops
    platoon_ops = platoon_ops
except Exception:
    platoon_ops = None
try:
    import intra_platoon_ops
    intra_ops = intra_platoon_ops
except Exception:
    intra_ops = None
try:
    import server as server_mod
except Exception:
    server_mod = None
try:
    import sumo_ops
except Exception:
    sumo_ops = None

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

def register_vehicle(vehicle_secret: str, manufacturer_signature: str) -> Optional[str]:
    """
    POST to NODE_URL/zkp/commitment and store commitment in DB.
    Returns the commitment string or None on failure.
    """
    data = {
        "vehicle_secret": vehicle_secret,
        "manufacturer_signature": manufacturer_signature
    }
    try:
        resp = requests.post(f"{NODE_URL}/zkp/commitment", json=data, timeout=5)
        resp.raise_for_status()
        commitment = resp.json().get("commitment")
        if commitment is not None:
            try:
                asyncio.run(insert_commitment(commitment))
            except Exception:
                # DB failure should not stop registration return
                pass
            return str(commitment)
    except Exception:
        return None
    return None

def auth_vehicle(commitment: str, vehicle_secret: str, manufacturer_signature: str,
                 capability_score: int, trust_token: str,
                 capability_threshold: int = 60, trust_threshold: int = 50) -> str:
    """
    Perform auth by building merkle proof (from DB) and calling NODE_URL/zkp/verify-vehicle.
    Returns status string ("ACCEPTED"/"REJECTED" or server returned status).
    """
    try:
        all_commitments = asyncio.run(get_commitments())
    except Exception:
        all_commitments = []

    if str(commitment) not in all_commitments:
        return "REJECTED"

    merkle = build_merkle(commitment, all_commitments)

    zkp_input = {
        "vehicle_secret": vehicle_secret,
        "manufacturer_signature": manufacturer_signature,
        "pathElements": merkle["pathElements"],
        "pathIndices": merkle["pathIndices"],
        "merkle_root": merkle["merkle_root"],
        "capability_score": capability_score,
        "trust_token": trust_token,
        "capability_threshold": capability_threshold,
        "trust_threshold": trust_threshold
    }

    try:
        resp = requests.post(f"{NODE_URL}/zkp/verify-vehicle", json=zkp_input, timeout=5)
        resp.raise_for_status()
        return resp.json().get("status", "REJECTED")
    except Exception:
        return "REJECTED"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUMO_GROUP = os.path.join(BASE_DIR, "sumo_platoon")
TMP_SUMOCFG = os.path.join(SUMO_GROUP, "tmp_generated.sumocfg")

STEP_LENGTH = 0.1
SIM_SECONDS = 270
SIM_STEPS = int(SIM_SECONDS / STEP_LENGTH)

FAST_SIM = True
SIM_SLEEP = 0.01 if FAST_SIM else STEP_LENGTH

PLATOON_COUNT = 2
PLATOON_SIZES = [6, 3]  
DEPART_BASE = 1.0
DEPART_GAP = 1.8
LEADER_SPEED_MPS = 12.0
PLATOON2_SPEED_MULTIPLIER = 1.35   
PLATOON2_MIN_SPEED = 5.0
PLATOON2_SLOW_K = 0.15        
LEAVE_AFTER_MERGE_SEC = 6.0

JUNCTION_TRIGGER_DIST = 60.0
SPAWN_AHEAD_SEC = 1.5
MERGE_APPROACH_DIST = 200.0

PLATOON_DESIRED_GAP = 20.0
PLATOON_CTRL_K = 0.6

MERGE_TARGET_DIST = 35.0       
MERGE_TOLERANCE = 0.75           
MERGE_SLOW_REGION = 120.0         

SIDE1_FORCE_SPAWN_STEP = 1340
SIDE1_ARRIVE_STEP = 1640

SLOW_START_STEP = 1620
MERGE_EXECUTE_STEP = 1800

LAST_VEHICLE_SWAP_STEP = int(SIM_STEPS * 0.85)

PLATOON_COLORS: List[Tuple[int,int,int,int]] = [
    (220, 20, 20, 255),
    (20, 140, 240, 255),
    (20, 220, 80, 255),
]

SELECTED_MAIN_EDGE = "main_0"
SELECTED_SIDE1_EDGE = "side1"
SELECTED_SIDE2_EDGE = "side2"

msg_q = queue.Queue()
cmd_q = queue.Queue()

rsu_positions: Dict[str, Tuple[float, float]] = {}
vid_confidence: Dict[str, float] = {}

def safe_put(q, s):
    try:
        q.put(s)
    except Exception:
        pass

# helper to apply a common color tuple to a list of vehicles
def _apply_common_platoon_color(vids: List[str], color: Tuple[int,int,int,int]):
    if not vids or color is None:
        return
    for v in vids:
        try:
            traci.vehicle.setColor(v, color)
        except Exception:
            try:
                traci.vehicle.setColor(v, list(color))
            except Exception:
                pass

# --- NEW helper: gather merged candidates robustly and enforce recolour + leader election ---
def _collect_and_force_recolour_merged(target_pidx: int, pids_map: Dict[int, Optional[str]], prefer_prefix: Optional[str] = None) -> Optional[str]:
    """
    Collect all vehicles that belong to the source platoons (index 0/1 or same pid),
    clear any 'colored' protection, set their platoon index to target_pidx, apply
    uniform colour and elect/highlight leader. Returns elected leader vid or None.
    """
    global vid_platoon_index, vid_to_pid, colored

    try:
        present = traci.vehicle.getIDList()
    except Exception:
        present = []

    candidates = set()
    # include vehicles by known index or pid
    for v in present:
        try:
            if vid_platoon_index.get(v) in (0, 1):
                candidates.add(v)
                continue
            if vid_to_pid.get(v) in (pids_map.get(0), pids_map.get(1)):
                candidates.add(v)
                continue
            # optionally include by naming prefix (fallback)
            if prefer_prefix and v.startswith(prefer_prefix):
                candidates.add(v)
        except Exception:
            continue

    if not candidates:
        return None

    vids = sorted(list(candidates))

    # remove protection so we can overwrite colours
    for v in vids:
        try:
            if v in colored:
                try:
                    colored.discard(v)
                except Exception:
                    try:
                        colored.remove(v)
                    except Exception:
                        pass
        except Exception:
            pass

    # set internal mappings and pid
    for v in vids:
        try:
            vid_platoon_index[v] = target_pidx
        except Exception:
            pass
        try:
            vid_to_pid[v] = pids_map.get(target_pidx)
        except Exception:
            pass

    # apply uniform colour
    try:
        colour = PLATOON_COLORS[target_pidx % len(PLATOON_COLORS)]
    except Exception:
        colour = PLATOON_COLORS[0]

    for v in vids:
        try:
            traci.vehicle.setColor(v, colour)
        except Exception:
            try:
                traci.vehicle.setColor(v, list(colour))
            except Exception:
                pass
        # mark as protected so per-step colouring won't override this assignment
        try:
            colored.add(v)
        except Exception:
            pass

    # elect leader and highlight
    try:
        leader = bully_elect_leader(vids) or vids[0]
        try:
            traci.vehicle.setColor(leader, (255, 240, 0, 255))
        except Exception:
            pass
        # ensure leader stays protected
        try:
            colored.add(leader)
        except Exception:
            pass
        return leader
    except Exception:
        return vids[0]

def overlay_thread(q, cmd_q):
    try:
        import tkinter as tk
    except Exception:
        return
    root = tk.Tk()
    root.title("Platoon Controls / Log")
    root.geometry("520x360+900+60")
    root.attributes("-topmost", True)
    f = tk.Frame(root); f.pack(side="top", fill="x")
    tk.Button(f, text="Quit SIM", width=12, command=lambda c="quit_sim": cmd_q.put(c)).pack(side="left", padx=4, pady=4)
    txt = tk.Text(root, bg="#111", fg="#fff", wrap="word", font=("Consolas",10))
    txt.pack(fill="both", expand=True, padx=6, pady=(0,6))
    def poll():
        stop = False
        while True:
            try:
                s = q.get_nowait()
            except queue.Empty:
                break
            if s == "__QUIT__":
                stop = True
                break
            try:
                txt.config(state="normal")
                txt.insert("end", f"{s}\n")
                txt.see("end")
                txt.config(state="disabled")
            except Exception:
                pass
        if stop:
            root.destroy()
            return
        root.after(200, poll)
    root.after(200, poll)
    root.mainloop()

def load_rsu_positions():
    global rsu_positions
    rsu_positions = {}
    cand = os.path.join(SUMO_GROUP, "rsu.add.xml")
    if os.path.exists(cand):
        try:
            tree = ET.parse(cand)
            root = tree.getroot()
            for poi in root.findall(".//poi"):
                pid = poi.get("id") or poi.get("name")
                x = poi.get("x"); y = poi.get("y")
                if pid and x and y:
                    try:
                        rsu_positions[pid] = (float(x), float(y))
                    except Exception:
                        continue
            safe_put(msg_q, f"[RSU] loaded {len(rsu_positions)} RSU POIs from rsu.add.xml")
            return
        except Exception:
            pass

    netp = find_file_in_sumogroup(["guindy.net.xml","guindy.net"])
    if netp and os.path.exists(netp):
        try:
            tree = ET.parse(netp)
            root = tree.getroot()
            idx = 0
            for node in root.findall(".//poi"):
                pid = node.get("id") or f"rsu_{idx}"
                x = node.get("x"); y = node.get("y")
                if pid and x and y:
                    try:
                        rsu_positions[pid] = (float(x), float(y)); idx += 1
                    except Exception:
                        continue
            safe_put(msg_q, f"[RSU] loaded {len(rsu_positions)} RSU POIs from net file")
            return
        except Exception:
            pass
    safe_put(msg_q, "[RSU] no rsu.add.xml found; RSU messaging will use nearest edge heuristic")

def get_nearest_rsu_for_position(x: float, y: float) -> Optional[str]:
    best_id = None; best_d = float("inf")
    try:
        for pid, (rx, ry) in rsu_positions.items():
            d = math.hypot(rx - x, ry - y)
            if d < best_d:
                best_d = d; best_id = pid
    except Exception:
        return None
    return best_id

def get_nearest_rsu_for_vid(vid: str) -> Optional[str]:
    try:
        pos = traci.vehicle.getPosition(vid)
        if pos:
            return get_nearest_rsu_for_position(pos[0], pos[1])
    except Exception:
        pass
    return None

def get_n_nearest_rsus_for_vid(vid: str, n: int = 3) -> List[str]:
    """
    Return up to n nearest RSU ids for vehicle vid, ordered by distance (closest first).
    """
    out: List[Tuple[float, str]] = []
    try:
        pos = traci.vehicle.getPosition(vid)
        if not pos:
            return []
        x, y = pos[0], pos[1]
        for pid, (rx, ry) in rsu_positions.items():
            try:
                d = math.hypot(rx - x, ry - y)
                out.append((d, pid))
            except Exception:
                continue
        out.sort(key=lambda t: t[0])
        return [pid for _, pid in out[:n]]
    except Exception:
        try:
            keys = list(rsu_positions.keys())[:n]
            return keys
        except Exception:
            return []

def find_sumo_binary():
    for name in ("sumo-gui", "sumo-gui.exe", "sumo", "sumo.exe"):
        p = shutil.which(name)
        if p:
            return p
    home = os.environ.get("SUMO_HOME")
    if home:
        for exe in ("bin/sumo-gui","bin/sumo-gui.exe","bin/sumo","bin/sumo.exe"):
            p = os.path.join(home, exe)
            if os.path.exists(p):
                return p
    return None

def parse_net_graph(net_path: str) -> Tuple[Dict[str, Tuple[str,str]], Dict[str, List[str]]]:
    edges: Dict[str, Tuple[str,str]] = {}
    outs: Dict[str, List[str]] = {}
    try:
        tree = ET.parse(net_path)
        root = tree.getroot()
        for edge in root.findall(".//edge"):
            eid = edge.get("id")
            if not eid or eid.startswith(":"):
                continue
            fromNode = edge.get("from")
            toNode = edge.get("to")
            if fromNode is None or toNode is None:
                continue
            edges[eid] = (fromNode, toNode)
            outs.setdefault(fromNode, []).append(eid)
    except Exception:
        return {}, {}
    return edges, outs

def build_connected_route_from_net(start_edge: str, edges: Dict[str, Tuple[str,str]], outs: Dict[str, List[str]], max_hops: int = 12) -> List[str]:
    route: List[str] = []
    if not start_edge or start_edge not in edges:
        return route
    visited = set()
    curr = start_edge
    route.append(curr); visited.add(curr)
    for _ in range(max_hops - 1):
        try:
            _, toNode = edges[curr]
        except Exception:
            break
        candidates = []
        for e in outs.get(toNode, []):
            if e in visited:
                continue
            if e.startswith(":"):
                continue
            candidates.append(e)
        if not candidates:
            break
        nxt = candidates[0]
        route.append(nxt); visited.add(nxt); curr = nxt
    return route

def parse_net_edge_ids(net_path: str, max_edges: int = 20) -> List[str]:
    out: List[str] = []
    try:
        tree = ET.parse(net_path)
        root = tree.getroot()
        for edge in root.findall(".//edge"):
            eid = edge.get("id")
            if eid and not eid.startswith(":"):
                out.append(eid)
                if len(out) >= max_edges:
                    break
    except Exception:
        return []
    return out

def ensure_sumocfg():
    net = find_file_in_sumogroup(["guindy.net.xml","guindy.net","guindy.net.xml.gz"])
    routes = find_file_in_sumogroup(["route.rou.xml","routes.rou.xml","route.rou"])
    if not net:
        raise FileNotFoundError("guindy.net.xml missing in sumo_platoon folder")
    if not routes:
        routes = os.path.join(SUMO_GROUP, "route.rou.xml")
        edge_ids = parse_net_edge_ids(net, max_edges=12)
        if not edge_ids:
            edge_ids = [SELECTED_MAIN_EDGE, SELECTED_SIDE1_EDGE, SELECTED_SIDE2_EDGE]
        edges_graph, outs = parse_net_graph(net)
        main_start = SELECTED_MAIN_EDGE if SELECTED_MAIN_EDGE in edge_ids else (edge_ids[0] if edge_ids else SELECTED_MAIN_EDGE)
        side1_start = SELECTED_SIDE1_EDGE if SELECTED_SIDE1_EDGE in edge_ids else (edge_ids[1] if len(edge_ids) > 1 else main_start)
        side2_start = SELECTED_SIDE2_EDGE if SELECTED_SIDE2_EDGE in edge_ids else (edge_ids[2] if len(edge_ids) > 2 else main_start)
        if edges_graph:
            r_main_list = build_connected_route_from_net(main_start, edges_graph, outs, max_hops=6) or [main_start]
            r_side1_list = build_connected_route_from_net(side1_start, edges_graph, outs, max_hops=4) or [side1_start]
            r_side2_list = build_connected_route_from_net(side2_start, edges_graph, outs, max_hops=4) or [side2_start]
        else:
            r_main_list = edge_ids[:4] if len(edge_ids) >= 4 else edge_ids
            r_side1_list = [side1_start]
            r_side2_list = [side2_start]
        r_main = " ".join(r_main_list)
        r_side1 = " ".join(r_side1_list)
        r_side2 = " ".join(r_side2_list)
        try:
            with open(routes, "w", encoding="utf8") as f:
                f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<routes>
  <vType id="car" accel="2.6" decel="4.5" sigma="0.5" length="4.5" maxSpeed="13.9"/>
  <route id="r_main" edges="{r_main}"/>
  <route id="r_side1" edges="{r_side1}"/>
  <route id="r_side2" edges="{r_side2}"/>
</routes>
""")
            safe_put(msg_q, f"[SUMO] generated short route file -> {routes}")
        except Exception as e:
            raise RuntimeError(f"failed to create default route file: {e}")
    with open(TMP_SUMOCFG,"w", encoding="utf8") as f:
        f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <input>
    <net-file value="{os.path.basename(net)}"/>
    <route-files value="{os.path.basename(routes)}"/>
    <additional-files value="rsu.add.xml"/>
  </input>
  <time>
    <begin value="0"/>
    <end value="{SIM_SECONDS}"/>
    <step-length value="{STEP_LENGTH}"/>
  </time>
  <gui>
    <start value="true"/>
  </gui>
</configuration>
""")
    safe_put(msg_q, f"[SUMO] using net/routes -> wrote {TMP_SUMOCFG}")
    return TMP_SUMOCFG

def find_file_in_sumogroup(candidates: List[str]) -> Optional[str]:
    for n in candidates:
        p = os.path.join(SUMO_GROUP, n)
        if os.path.exists(p):
            return p
    if os.path.isdir(SUMO_GROUP):
        for f in os.listdir(SUMO_GROUP):
            if f.lower() in [c.lower() for c in candidates]:
                return os.path.join(SUMO_GROUP, f)
    return None

def plate_for(pidx, vidx): return f"P{pidx+1}-{vidx+1:02d}"
def vid_for(pidx, vidx): return f"v_p{pidx+1}_{vidx+1}"

def lane_allows_cars(lane_id: str) -> bool:
    try:
        allowed = traci.lane.getAllowed(lane_id)
    except Exception:
        return True
    if not allowed:
        return True
    for a in allowed:
        if a in ("passenger","car","all"):
            return True
    return False

def edge_allows_cars(edge_id: str) -> bool:
    try:
        lanes = traci.edge.getLaneNumber(edge_id)
    except Exception:
        return False
    for i in range(lanes):
        lid = f"{edge_id}_{i}"
        try:
            if lane_allows_cars(lid):
                return True
        except Exception:
            continue
    return False

def choose_candidate_edges(max_needed: int = 10) -> List[str]:
    out = []
    try:
        edges = traci.edge.getIDList()
    except Exception:
        return out
    for e in edges:
        try:
            if edge_allows_cars(e) and not e.startswith(":"):
                out.append(e)
                if len(out) >= max_needed:
                    break
        except Exception:
            continue
    return out

def compute_merge_point(edge_a: str, edge_b: str, forward_dist: float = 40.0) -> Optional[Tuple[float,float]]:
    try:
        sa = traci.edge.getShape(edge_a); sb = traci.edge.getShape(edge_b)
    except Exception:
        return None
    if not sa or not sb:
        return None
    aend = sa[-1]; bend = sb[-1]
    mx = (aend[0]+bend[0])/2.0; my = (aend[1]+bend[1])/2.0
    dir_a = (aend[0]-sa[0][0], aend[1]-sa[0][1])
    dir_b = (bend[0]-sb[0][0], bend[1]-sb[0][1])
    dax = dir_a[0]+dir_b[0]; day = dir_a[1]+dir_b[1]
    n = math.hypot(dax,day) or 1.0
    return (mx + dax/n*forward_dist, my + day/n*forward_dist)

def safe_set_vehicle_route(vid: str, target_edges: List[str]) -> bool:
    try:
        if not target_edges:
            return False
        if vid not in traci.vehicle.getIDList():
            return False
        curr = traci.vehicle.getRoadID(vid)
        if not curr:
            try:
                traci.vehicle.changeTarget(vid, target_edges[0])
                return True
            except Exception:
                return False
        if curr == target_edges[0]:
            try:
                traci.vehicle.setRoute(vid, target_edges)
                return True
            except Exception:
                pass
        if curr in target_edges:
            idx = target_edges.index(curr)
            sub = target_edges[idx:]
            try:
                traci.vehicle.setRoute(vid, sub)
                return True
            except Exception:
                pass
        try:
            traci.vehicle.changeTarget(vid, target_edges[0])
            return True
        except Exception:
            return False
    except Exception:
        return False

def _call_grpc_fn(fn_names: List[str], *args, **kwargs):
    """
    Try to call any function name from fn_names across imported helper modules.
    Returns the first non-exception result, or None if none succeeded.
    """
    modules = [sumo_ops, grpc_client, platoon_ops, intra_ops, server_mod]
    for m in modules:
        if not m:
            continue
        for name in fn_names:
            try:
                fn = getattr(m, name, None)
                if callable(fn):
                    try:
                        return fn(*args, **kwargs)
                    except TypeError:
                        try:
                            return fn(*args)
                        except Exception:
                            try:
                                return fn()
                            except Exception:
                                continue
                    except Exception:
                        continue
            except Exception:
                continue
    return None

def rsu_auth_and_join(_, plate, pid=None, rsu_id: Optional[str]=None):
    res = _call_grpc_fn(["rsu_auth_and_join", "auth_and_join", "join_platoon", "join", "join_rsu"], plate, pid, rsu_id=rsu_id)
    if res:
        return res

    prefix = plate.split("-")[0]
    if rsu_id:
        safe_put(msg_q, f"[RSU {rsu_id}] auth/join request for {plate}")

    secret = int(plate.split("-")[1])  # using plate as a simple secret in this fallback

    vehicle_secret = 3000 + secret  # using plate as a simple secret in this fallback
    manufacturer_signature = 4000 + secret  # using plate as a simple signature in this fallback
    print(f"Attempting registration for {plate}")
    

    commitment = register_vehicle(vehicle_secret, manufacturer_signature)
    print(f"Registration result for {plate}: commitment={commitment}")

    if commitment:
        safe_put(msg_q, f"[RSU] registered {plate} -> commitment {commitment}")
        # return commitment as a join identifier (pid) in fallback mode
        return commitment
    
    return pid or f"mock-{prefix}"

def do_merge(_, leader, src, dst, rsu_id: Optional[str]=None):
    res = _call_grpc_fn(["do_merge", "merge", "merge_platoons", "request_merge", "sumo_merge"], leader, src, dst, rsu_id=rsu_id)
    if res:
        return res

    if rsu_id:
        safe_put(msg_q, f"[RSU {rsu_id}] merge request: leader={leader} src={src} dst={dst}")
    class R: pass
    r = R(); r.ok = (src != dst); r.message = None
    return r

def do_leave(_, plate, rsu_id: Optional[str]=None):
    res = _call_grpc_fn(["do_leave", "leave", "leave_platoon", "request_leave", "sumo_leave"], plate, rsu_id=rsu_id)
    if res:
        return res

    if rsu_id:
        safe_put(msg_q, f"[RSU {rsu_id}] leave request for {plate}")
    class R: pass
    r = R(); r.ok = True; return r

def resolve_side_spawn_edge(side_idx: int, edges_graph: Dict[str, Tuple[str,str]], candidate_edge: Optional[str]) -> Optional[str]:
    try:
        if not edges_graph:
            return candidate_edge
        key = "side1" if side_idx == 1 else "side2"
        for e in edges_graph.keys():
            if key in e:
                return e
        target_end = f"s{side_idx}b"
        target_start = f"s{side_idx}a"
        for e, (fr, to) in edges_graph.items():
            if to == target_end or fr == target_start:
                return e
    except Exception:
        pass
    return candidate_edge

def _vid_election_value(vid: str) -> int:
    try:
        m = re.match(r"v_p(\d+)_(\d+)", vid)
        if m:
            p = int(m.group(1)); i = int(m.group(2))
            return p * 100 + i
    except Exception:
        pass
    return abs(hash(vid)) % 100000

def bully_elect_leader(candidates: List[str]) -> Optional[str]:
    """
    Elect leader using per-vehicle confidence scores first (higher is better).
    Tie-breaker: numeric election value derived from vid.
    """
    if not candidates:
        return None

    for v in candidates:
        if v not in vid_confidence:
            try:
                vid_confidence[v] = float(random.random())
                safe_put(msg_q, f"[CONF] assigned {v} confidence={vid_confidence[v]:.3f}")
            except Exception:
                vid_confidence[v] = 0.0

    best = None
    best_conf = -1.0
    ties: List[str] = []
    for v in candidates:
        try:
            c = float(vid_confidence.get(v, 0.0))
        except Exception:
            c = 0.0
        if c > best_conf + 1e-9:
            best_conf = c
            best = v
            ties = [v]
        elif abs(c - best_conf) <= 1e-9:
            ties.append(v)

    if len(ties) > 1:
        chosen = None
        best_val = -1
        for v in ties:
            try:
                val = _vid_election_value(v)
                if val > best_val:
                    best_val = val
                    chosen = v
            except Exception:
                continue
        return chosen or best
    return best

def synchronize_platoon_to_leader(vids: List[str], leader_vid: str, lane_change_duration: float = 2.0):
    try:
        _call_grpc_fn(["synchronize_platoon_to_leader", "sync_platoon", "sync"], vids, leader_vid)
    except Exception:
        pass
    try:
        leader_speed = LEADER_SPEED_MPS
        leader_lane = 0
        try:
            leader_speed = float(traci.vehicle.getSpeed(leader_vid))
        except Exception:
            leader_speed = LEADER_SPEED_MPS
        try:
            leader_lane = int(traci.vehicle.getLaneIndex(leader_vid))
        except Exception:
            leader_lane = 0
        for v in vids:
            try:
                traci.vehicle.setSpeedMode(v, 0)
            except Exception:
                pass
            try:
                traci.vehicle.changeLane(v, leader_lane, lane_change_duration)
            except Exception:
                pass
            try:
                traci.vehicle.setSpeed(v, leader_speed)
            except Exception:
                try:
                    traci.vehicle.slowDown(v, leader_speed, 1.0)
                except Exception:
                    pass
    except Exception:
        pass

def get_view_id() -> str:
    """
    Return a GUI view id usable with traci.gui.trackVehicle().
    Tries to return the first available view id from SUMO; if none found returns empty string.
    """
    try:
        vids = traci.gui.getIDList()
        if vids:
            return vids[0]
    except Exception:
        pass

    for candidate in ("View #0", "View #1", "View 0", "MainView"):
        try:
            if candidate in traci.gui.getIDList():
                return candidate
        except Exception:
            continue
    return ""

def pick_merge_edges_for_vid(vid: str, main_route_edges: List[str], preferred_main: str = "main_1") -> List[str]:
    try:
        res = _call_grpc_fn(["pick_merge_edges_for_vid", "recommend_merge_route", "choose_merge_route"], vid, main_route_edges, preferred_main)
        if isinstance(res, list) and res:
            return res
    except Exception:
        pass
    try:
        if not main_route_edges:
            return main_route_edges
        if preferred_main in main_route_edges:
            idx = main_route_edges.index(preferred_main)
            return main_route_edges[idx:]
        try:
            curr = traci.vehicle.getRoadID(vid)
        except Exception:
            curr = None
        if curr and curr in main_route_edges:
            idx = main_route_edges.index(curr)
            return main_route_edges[idx:]
    except Exception:
        pass
    return main_route_edges

def _ensure_vehicle_speed_and_lane(vid: str, speed: float, lane: int = 0, lane_change_time: float = 1.5):
    try:
        if vid not in traci.vehicle.getIDList():
            return
        try:
            traci.vehicle.setSpeedMode(vid, 0)
        except Exception:
            pass
        try:
            traci.vehicle.setSpeed(vid, speed)
        except Exception:
            try:
                traci.vehicle.slowDown(vid, speed, 0.5)
            except Exception:
                pass
        try:
            traci.vehicle.changeLane(vid, lane, lane_change_time)
        except Exception:
            pass
    except Exception:
        pass

def _slowdown_platoon2_towards(leader_speed: float, gap: float):
    """
    Gradually slow down the platoon-2 head only to help close the gap between v_p1_3 and v_p2_1.
    gap = current tail(head) distance - target; positive -> need to reduce gap.
    """
    if gap <= 0.0:
        return
    decel = min(6.0, max(0.5, gap * PLATOON2_SLOW_K))
    target_speed = max(PLATOON2_MIN_SPEED, leader_speed - decel)

    head_vid = vid_for(1, 0)
    try:
        if head_vid in traci.vehicle.getIDList():
            try:
                traci.vehicle.setSpeedMode(head_vid, 0)
            except Exception:
                pass
            try:
                traci.vehicle.slowDown(head_vid, float(target_speed), 0.8)
            except Exception:
                try:
                    traci.vehicle.setSpeed(head_vid, float(target_speed))
                except Exception:
                    pass
            try:
                lead1 = vid_for(0, 0)
                if lead1 in traci.vehicle.getIDList():
                    lane_idx = traci.vehicle.getLaneIndex(lead1)
                    traci.vehicle.changeLane(head_vid, lane_idx, 1.0)
            except Exception:
                pass
    except Exception:
        pass

def _find_free_platoon_index(pids_map: Dict[int, Optional[str]], vid_platoon_index_map: Dict[str,int], present_ids: List[str]) -> int:
    for i in range(PLATOON_COUNT):
        has = False
        for v in present_ids:
            if vid_platoon_index_map.get(v) == i:
                has = True
                break
        if not has:
            return i

    max_idx = max(list(pids_map.keys()) or [PLATOON_COUNT-1])
    return max_idx + 1

def main():
    threading.Thread(target=overlay_thread, args=(msg_q, cmd_q), daemon=True).start()
    if traci is None:
        safe_put(msg_q, "[ERROR] traci not found")
        return

    try:
        cfg = ensure_sumocfg()
    except Exception as e:
        safe_put(msg_q, f"[ERROR] {e}")
        return

    sumo_bin = find_sumo_binary()
    if not sumo_bin:
        safe_put(msg_q, "[ERROR] SUMO binary not found")
        return

    safe_put(msg_q, f"[SUMO] starting: {sumo_bin} -c {cfg} --step-length {STEP_LENGTH}")
    try:
        traci.start([sumo_bin, "-c", cfg, "--step-length", str(STEP_LENGTH)])
    except Exception as e:
        safe_put(msg_q, f"[ERROR] traci.start failed: {e}")
        return

    try:
        traci.simulationStep(); time.sleep(SIM_SLEEP)
    except Exception:
        pass

    try:
        load_rsu_positions()
    except Exception:
        safe_put(msg_q, "[RSU] failed to load RSU POIs")

    try:
        traci.simulationStep(); time.sleep(SIM_SLEEP)
    except Exception:
        pass

    all_edges = []
    try:
        all_edges = traci.edge.getIDList()
    except Exception:
        safe_put(msg_q, "[ERROR] failed to list edges")
    cand = choose_candidate_edges(50)

    main_edges = []
    if SELECTED_MAIN_EDGE in all_edges and edge_allows_cars(SELECTED_MAIN_EDGE):
        main_edges = [SELECTED_MAIN_EDGE]
    if not main_edges and cand:
        main_edges = cand[:2]
    if not main_edges and all_edges:
        main_edges = [e for e in all_edges if not e.startswith(":")][:1]

    side1_edge = "side1_connector" if "side1_connector" in all_edges else (cand[2] if len(cand)>2 else (all_edges[1] if len(all_edges)>1 else main_edges[0]))
    side2_edge = SELECTED_SIDE2_EDGE if (SELECTED_SIDE2_EDGE in all_edges and edge_allows_cars(SELECTED_SIDE2_EDGE)) else (cand[3] if len(cand) > 3 else (all_edges[2] if len(all_edges) > 2 else main_edges[0]))

    try:
        existing_routes = traci.route.getIDList()
    except Exception:
        existing_routes = []
    try:
        net_path = find_file_in_sumogroup(["guindy.net.xml","guindy.net"])
        edges_graph, outs = ({}, {}) if not net_path else parse_net_graph(net_path)
        main_start = main_edges[0] if main_edges else (cand[0] if cand else (all_edges[0] if all_edges else None))
        side1_start = side1_edge
        side2_start = side2_edge
        if edges_graph and main_start:
            r_main_edges = build_connected_route_from_net(main_start, edges_graph, outs, max_hops=6) or [main_start]
            r_side1_edges = build_connected_route_from_net(side1_start, edges_graph, outs, max_hops=4) or [side1_start]
            r_side2_edges = build_connected_route_from_net(side2_start, edges_graph, outs, max_hops=4) or [side2_start]
        else:
            r_main_edges = [e for e in cand[:4] if not e.startswith(":")] if cand else ([main_start] if main_start else [])
            r_side1_edges = [side1_start] if side1_start and not side1_start.startswith(":") else []
            r_side2_edges = [side2_start] if side2_start and not side2_start.startswith(":") else []
        if r_main_edges and "r_main" not in existing_routes:
            traci.route.add("r_main", r_main_edges)
            safe_put(msg_q, f"[SUMO] runtime r_main edges: {r_main_edges}")
        if r_side1_edges and "r_side1" not in existing_routes:
            traci.route.add("r_side1", r_side1_edges)
        if r_side2_edges and "r_side2" not in existing_routes:
            traci.route.add("r_side2", r_side2_edges)
    except Exception as e:
        safe_put(msg_q, f"[SUMO] failed to create runtime routes: {e}")

    vid_to_plate = {}
    vid_to_pid = {}
    vid_platoon_index = {}
    try:
        existing_vehicles = set(traci.vehicle.getIDList())
    except Exception:
        existing_vehicles = set()

    for vidx in range(PLATOON_SIZES[0]):
        vid = vid_for(0, vidx)
        plate = plate_for(0, vidx)
        depart = str(DEPART_BASE + vidx * DEPART_GAP)
        if vid in existing_vehicles:
            safe_put(msg_q, f"[SUMO] vehicle {vid} already present; skipping add")
        else:
            try:
                traci.vehicle.add(vid, "r_main", typeID="car", depart=depart)
            except Exception:
                try:
                    traci.vehicle.add(vid, "r_main", depart=depart)
                except Exception:
                    try:
                        e0 = main_edges[0] if main_edges else None
                        if e0:
                            traci.vehicle.add(vid, e0, depart=depart)
                    except Exception as e_final:
                        safe_put(msg_q, f"[SUMO] failed to add {vid}: {e_final}")
                        continue
        vid_to_plate[vid] = plate
        vid_to_pid[vid] = None
        vid_platoon_index[vid] = 0

        try:
            vid_confidence[vid] = float(random.random())
            safe_put(msg_q, f"[CONF] {vid} confidence={vid_confidence[vid]:.3f}")
        except Exception:
            pass
        try:
            _ensure_vehicle_speed_and_lane(vid, LEADER_SPEED_MPS, lane=0, lane_change_time=1.0)
        except Exception:
            pass

    junction1 = junction2 = None
    try:
        main_shape = []
        if main_edges:
            for e in main_edges:
                try:
                    s = traci.edge.getShape(e)
                    if s:
                        main_shape += s
                except Exception:
                    pass
        if main_shape:
            ln = len(main_shape)
            idx1 = max(1, int(ln * 0.30))
            idx2 = max(1, int(ln * 0.60))
            junction1 = main_shape[idx1] if idx1 < ln else main_shape[-1]
            junction2 = main_shape[idx2] if idx2 < ln else main_shape[-1]
            safe_put(msg_q, f"[SUMO] junction1 at {junction1}, junction2 at {junction2}")
    except Exception:
        junction1 = junction2 = None

    planned_side_spawns = {
        1: {"edge": "side1_connector", "junction": junction1, "spawned": False},
        2: {"edge": side2_edge, "junction": junction2, "spawned": False}
    }

    colored = set()
    pids: Dict[int, Optional[str]] = {i: None for i in range(PLATOON_COUNT)}
    joined = {}
    leader_reported = {i: False for i in range(PLATOON_COUNT)}
    prev_highlighted: set = set()

    step = 0
    merge_attempted = False
    merged_done = False
    middle_left_done = False  

    merged_vids: List[str] = []

    view = get_view_id()
    try:
        traci.gui.trackVehicle(view, "v_p1_1")
        traci.gui.setZoom(view, 250.0)
    except Exception:
        pass

    try:
        while step < SIM_STEPS:
            try:
                cmd = cmd_q.get_nowait()
            except queue.Empty:
                cmd = None
            if cmd == "quit_sim":
                safe_put(msg_q, "[CTRL] Quit requested")
                break

            try:
                traci.simulationStep()
            except FatalTraCIError as fte:
                safe_put(msg_q, f"[ERROR] Connection closed by SUMO during simulation: {fte}")
                break

            sim_time = step * STEP_LENGTH
            present = set(traci.vehicle.getIDList())

            try:
                current_edges = set()
                for v in present:
                    try:
                        eid = traci.vehicle.getRoadID(v)
                    except Exception:
                        eid = None
                    if eid:
                        current_edges.add(eid)
                for e in current_edges:
                    try:
                        traci.edge.setColor(e, (255, 160, 0, 255))
                    except Exception:
                        try:
                            traci.edge.setColor(e, [255, 160, 0, 255])
                        except Exception:
                            pass
                for e in list(prev_highlighted - current_edges):
                    if e in main_edges or e in (planned_side_spawns[1]["edge"], planned_side_spawns[2]["edge"]):
                        continue
                    try:
                        traci.edge.setColor(e, (0, 0, 0, 0))
                    except Exception:
                        pass
                prev_highlighted = current_edges
            except Exception:
                pass

            try:
                for vid in present:
                    if vid in vid_platoon_index and vid not in colored:
                        pidx = vid_platoon_index[vid]
                        color = PLATOON_COLORS[pidx % len(PLATOON_COLORS)]
                        try:
                            traci.vehicle.setColor(vid, color)
                        except Exception:
                            try:
                                traci.vehicle.setColor(vid, list(color))
                            except Exception:
                                pass
                        colored.add(vid)
            except Exception:
                pass

            for vid, plate in list(vid_to_plate.items()):
                if vid in present and not joined.get(vid, False):
                    pidx = vid_platoon_index[vid]
                    requested_pid = pids.get(pidx)

                    rsu_id = get_nearest_rsu_for_vid(vid)
                    pid = _call_grpc_fn(["rsu_auth_and_join", "auth_and_join", "join_platoon", "join", "join_rsu"], plate, requested_pid, rsu_id=rsu_id)
                    if not pid:
                        pid = rsu_auth_and_join(None, plate, pid=requested_pid, rsu_id=rsu_id)
                    if pid:
                        joined[vid] = True
                        if pids.get(pidx) is None:
                            pids[pidx] = pid
                            if rsu_id:
                                safe_put(msg_q, f"[RSU {rsu_id}] Platoon {pidx} created pid={pid} by {plate}")
                            else:
                                safe_put(msg_q, f"[RSU] Platoon {pidx} created pid={pid} by {plate}")
                        else:
                            if requested_pid is None and pid != pids[pidx]:
                                pids[pidx] = pid
                        if rsu_id:
                            safe_put(msg_q, f"[RSU {rsu_id}] {plate} joined pid={pids[pidx]}")
                        else:
                            safe_put(msg_q, f"[RSU] {plate} joined pid={pids[pidx]}")
                    if vid.endswith("_1") and joined.get(vid, False) and not leader_reported.get(pidx, False):
                        leader_reported[pidx] = True

            try:
                leader_vid = vid_for(0, 0)
                if leader_vid in present:
                    leader_pos = traci.vehicle.getPosition(leader_vid)
                    for side_idx in (1, 2):
                        ps = planned_side_spawns[side_idx]
                        if not ps["spawned"] and ps["junction"] is not None:
                            d = math.hypot(leader_pos[0] - ps["junction"][0], leader_pos[1] - ps["junction"][1])
                            if d <= JUNCTION_TRIGGER_DIST:
                                resolved_edge = ps.get("edge")
                                try:
                                    net_path = find_file_in_sumogroup(["guindy.net.xml","guindy.net"])
                                    edges_graph, _ = ({}, {}) if not net_path else parse_net_graph(net_path)
                                    resolved_edge = resolve_side_spawn_edge(side_idx, edges_graph, ps.get("edge"))
                                except Exception:
                                    resolved_edge = ps.get("edge")
                                safe_put(msg_q, f"[EVENT] main leader near junction{side_idx} (d={d:.1f}) -> spawning Platoon {side_idx+1} from {resolved_edge}")
                                for vidx in range(PLATOON_SIZES[side_idx]):
                                    vid = vid_for(side_idx, vidx)
                                    plate = plate_for(side_idx, vidx)
                                    depart_time = sim_time + SPAWN_AHEAD_SEC + vidx * DEPART_GAP
                                    chosen_route = f"r_side{side_idx}"
                                    added_ok = False
                                    try:
                                        if chosen_route in traci.route.getIDList():
                                            traci.vehicle.add(vid, chosen_route, depart=str(depart_time))
                                            added_ok = True
                                        else:
                                            if resolved_edge:
                                                tmp_r = f"tmp_side{side_idx}_{vid}_{int(time.time()*1000)}"
                                                try:
                                                    traci.route.add(tmp_r, [resolved_edge])
                                                    traci.vehicle.add(vid, tmp_r, depart=str(depart_time))
                                                    added_ok = True
                                                except Exception:
                                                    pass
                                    except Exception:
                                        pass
                                    if not added_ok:
                                        try:
                                            start_edge = resolved_edge or ps.get("edge")
                                            if start_edge:
                                                traci.vehicle.add(vid, start_edge, depart=str(depart_time))
                                                added_ok = True
                                        except Exception as e_add:
                                            safe_put(msg_q, f"[SUMO] failed to spawn {vid} at junction{side_idx}: {e_add}")
                                            continue
                                    vid_to_plate[vid] = plate
                                    vid_to_pid[vid] = None
                                    vid_platoon_index[vid] = side_idx
             
                                    try:
                                        vid_confidence[vid] = float(random.random())
                                        safe_put(msg_q, f"[CONF] {vid} confidence={vid_confidence[vid]:.3f}")
                                    except Exception:
                                        pass
                                
                                    try:
                                        if side_idx == 1:
                                            faster_speed = min(LEADER_SPEED_MPS * PLATOON2_SPEED_MULTIPLIER, 30.0)
                                            _ensure_vehicle_speed_and_lane(vid, faster_speed, lane=1, lane_change_time=1.0)
                                        else:
                                            _ensure_vehicle_speed_and_lane(vid, LEADER_SPEED_MPS, lane=0, lane_change_time=1.0)
                                    except Exception:
                                        pass
                                ps["spawned"] = True
            except Exception:
                pass

            if step == SIDE1_FORCE_SPAWN_STEP and not planned_side_spawns[1]["spawned"]:
                safe_put(msg_q, f"[FORCED] Step {step}: spawning Platoon-2 on 'side1_connector' -> 'main_1' route")
                try:
                    start_edge = "side1_connector"
                    forced_edges = [start_edge]
                    try:
                        if "r_main" in traci.route.getIDList():
                            main_route_edges = traci.route.getEdges("r_main")
                        else:
                            main_route_edges = main_edges[:]
                    except Exception:
                        main_route_edges = main_edges[:]
                    if "main_1" in main_route_edges:
                        idx = main_route_edges.index("main_1")
                        for me in main_route_edges[idx:]:
                            if me not in forced_edges:
                                forced_edges.append(me)
                    else:
                        for me in main_route_edges:
                            if me not in forced_edges:
                                forced_edges.append(me)
                except Exception:
                    forced_edges = [ "side1_connector", "main_1", "main_2", "main_3" ]

                tmp_rid = f"r_forced_side1_{int(time.time()*1000)}"
                try:
                    traci.route.add(tmp_rid, forced_edges)
                except Exception as e:
                    safe_put(msg_q, f"[SUMO] failed to add forced route {tmp_rid}: {e}")
                    tmp_rid = None

                for vidx in range(PLATOON_SIZES[1]):
                    vid = vid_for(1, vidx)
                    plate = plate_for(1, vidx)
                    try:
                        if tmp_rid and tmp_rid in traci.route.getIDList():
                            traci.vehicle.add(vid, tmp_rid, typeID="car", depart=str(sim_time + 0.05))
                        else:
                            try:
                                traci.vehicle.add(vid, "side1_connector", depart=str(sim_time + 0.05), departPos="last")
                            except Exception:
                                traci.vehicle.add(vid, "side1_connector", depart=str(sim_time + 0.05))
                        try:
                            if vid in traci.vehicle.getIDList():
                                traci.vehicle.setSpeedMode(vid, 0)
                                faster_speed = min(LEADER_SPEED_MPS * PLATOON2_SPEED_MULTIPLIER, 30.0)
                                try:
                                    traci.vehicle.setSpeed(vid, faster_speed)
                                except Exception:
                                    traci.vehicle.slowDown(vid, faster_speed, 0.5)
                                try:
                                    traci.vehicle.changeLane(vid, 1, 1.5)
                                except Exception:
                                    pass
                                try:
                                    traci.vehicle.changeTarget(vid, "main_1")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    except Exception as e_add:
                        safe_put(msg_q, f"[SUMO] forced spawn failed for {vid}: {e_add}")
                        continue
                    vid_to_plate[vid] = plate
                    vid_to_pid[vid] = None
                    vid_platoon_index[vid] = 1
    
                    try:
                        vid_confidence[vid] = float(random.random())
                        safe_put(msg_q, f"[CONF] {vid} confidence={vid_confidence[vid]:.3f}")
                    except Exception:
                        pass

                planned_side_spawns[1]["spawned"] = True
                safe_put(msg_q, f"[FORCED] Platoon-2 spawned on {forced_edges[:6]}{'...' if len(forced_edges)>6 else ''}")

            try:
                if (not merged_done) and (not merge_attempted):
                    p1_tail = vid_for(0, PLATOON_SIZES[0]-1)   
                    p2_head = vid_for(1, 0)             
                    if p1_tail in present and p2_head in present:
                        p1_pos = traci.vehicle.getPosition(p1_tail)
                        p2_pos = traci.vehicle.getPosition(p2_head)
                        tail_to_head = math.hypot(p1_pos[0] - p2_pos[0], p1_pos[1] - p2_pos[1])

                        if step >= SLOW_START_STEP and tail_to_head > (MERGE_TARGET_DIST + MERGE_TOLERANCE):
                            try:
                                lead1 = vid_for(0,0)
                                leader_speed = float(traci.vehicle.getSpeed(lead1)) if lead1 in traci.vehicle.getIDList() else LEADER_SPEED_MPS
                            except Exception:
                                leader_speed = LEADER_SPEED_MPS
                            gap_excess = tail_to_head - MERGE_TARGET_DIST
                            if gap_excess > 0:
                                _slowdown_platoon2_towards(leader_speed, gap_excess)
                                print(f"[PLATOON] slowing Platoon-2 head to close gap ({tail_to_head:.1f}m -> target {MERGE_TARGET_DIST}m)")

                        if step >= MERGE_EXECUTE_STEP and tail_to_head <= (MERGE_TARGET_DIST + MERGE_TOLERANCE):
                            try:
                                lead1 = vid_for(0,0)
                                leader_speed = float(traci.vehicle.getSpeed(lead1)) if lead1 in traci.vehicle.getIDList() else LEADER_SPEED_MPS
                            except Exception:
                                leader_speed = LEADER_SPEED_MPS
             
                            for i in range(PLATOON_SIZES[1]):
                                vid = vid_for(1, i)
                                try:
                                    if vid in traci.vehicle.getIDList():
                                        traci.vehicle.slowDown(vid, float(leader_speed), 0.8)
                                        try:
                                            if vid_for(0,0) in traci.vehicle.getIDList():
                                                lane_idx = traci.vehicle.getLaneIndex(vid_for(0,0))
                                                traci.vehicle.changeLane(vid, lane_idx, 1.2)
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
     
                            safe_put(msg_q, f"[PLATOON] head {p2_head} -> requesting merge")
                            if pids.get(0) is None:
                                pids[0] = rsu_auth_and_join(None, plate_for(0,0))
                            if pids.get(1) is None:
                                pids[1] = rsu_auth_and_join(None, plate_for(1,0))
                            leader_plate = plate_for(0,0)
    
                            rsu_for_leader = get_nearest_rsu_for_vid(vid_for(0,0))
                            resp = _call_grpc_fn(["do_merge", "merge", "merge_platoons", "request_merge", "sumo_merge"], leader_plate, pids.get(0), pids.get(1), rsu_id=rsu_for_leader)
                            
                            do_merge(None, leader_plate, pids.get(0), pids.get(1))
                            if resp and getattr(resp, "ok", False):
                                merge_attempted = True
                            else:
                                safe_put(msg_q, f"[PLATOON] proximity merge rejected by server: {getattr(resp,'message',None)}")

                                # robustly collect merged vehicles and force recolour+leader election
                            merged_leader = _collect_and_force_recolour_merged(0, pids, prefer_prefix="v_p2_")
                            if not merged_leader:
                                    # fallback: elect leader from two tails/heads
                                merged_vids = []
                                for v in traci.vehicle.getIDList():
                                    if vid_platoon_index.get(v) in (0,1):
                                        merged_vids.append(v)
                                if not merged_vids:
                                    merged_vids = [p1_tail, p2_head]
                                merged_leader = bully_elect_leader(merged_vids) or p1_tail
   
                                _apply_common_platoon_color(merged_vids, PLATOON_COLORS[0])

                                try:
                                    for v in merged_vids:
                                        vid_platoon_index[v] = 0
                                        vid_to_pid[v] = pids.get(0)
                                        colored.add(v)
                                except Exception:
                                    pass

                                try:
                                    view = get_view_id()
                                    if view:
                                        traci.gui.trackVehicle(view, merged_leader)
                                except Exception:
                                    pass

                                synchronize_platoon_to_leader([v for v in traci.vehicle.getIDList() if vid_platoon_index.get(v) == 0], merged_leader)
                                merged_done = True
                                merged_at = sim_time
                                safe_put(msg_q, f"[PLATOON] merged (proximity): elected leader {merged_leader}, synced vehicles")
                            
            except Exception:
                pass

            if step == SIDE1_ARRIVE_STEP and not merge_attempted:
                p1_tail = vid_for(0, PLATOON_SIZES[0]-1)
                p2_head = vid_for(1, 0)
                if p1_tail in traci.vehicle.getIDList() and p2_head in traci.vehicle.getIDList():
                    try:
                        p1_pos = traci.vehicle.getPosition(p1_tail)
                        p2_pos = traci.vehicle.getPosition(p2_head)
                        tail_to_head = math.hypot(p1_pos[0] - p2_pos[0], p1_pos[1] - p2_pos[1])
                    except Exception:
                        tail_to_head = 9999.0

                    # Do not force merge here. Instead prepare by slowing Platoon-2 head
                    try:
                        lead1 = vid_for(0,0)
                        leader_speed = float(traci.vehicle.getSpeed(lead1)) if lead1 in traci.vehicle.getIDList() else LEADER_SPEED_MPS
                    except Exception:
                        leader_speed = LEADER_SPEED_MPS

                    gap_excess = max(0.0, tail_to_head - MERGE_TARGET_DIST)
                    if gap_excess < 0:
                        _slowdown_platoon2_towards(leader_speed, gap_excess)
                        safe_put(msg_q, f"[FORCED-ARRIVE] Step {step}: Platoon-2 head slowed to close gap ({tail_to_head:.1f}m -> target {MERGE_TARGET_DIST}m)")
                    else:
                        safe_put(msg_q, f"[PLATOON] FORCED merge rejected by server")

            if step == 2300 and not middle_left_done:
                try:
                    chosen_vid = None
                    chosen_pidx = None
                    for pidx in range(PLATOON_COUNT):
                        # select 3rd vehicle (index 2) instead of 2nd (index 1)
                        mid_vid = vid_for(pidx, 2)
                        if mid_vid in traci.vehicle.getIDList():
                             chosen_vid = mid_vid
                             chosen_pidx = pidx
                             break
                    if chosen_vid:
                        # perform leave for the 3rd vehicle of the chosen platoon
                        leave_plate = plate_for(chosen_pidx, 2)
                        leave_resp = _call_grpc_fn(["do_leave", "leave", "leave_platoon", "request_leave", "sumo_leave"], leave_plate)
                        if leave_resp is None:
                            try:
                                do_leave(None, leave_plate)
                            except Exception:
                                pass
                        try:
                            old_sp = float(traci.vehicle.getSpeed(chosen_vid))
                        except Exception:
                            old_sp = LEADER_SPEED_MPS
           
                        if step % 2 == 0:
                            new_sp = min(old_sp * 1.2, 30.0)
                        else:
                            new_sp = max(old_sp * 0.8, PLATOON2_MIN_SPEED)
        
                        try:
                            cur_lane = traci.vehicle.getLaneIndex(chosen_vid)
                        except Exception:
                            cur_lane = 0
        
                        target_lane = 3
                        try:
                            traci.vehicle.changeLane(chosen_vid, target_lane, 1.5)
                        except Exception:
                            try:
                                traci.vehicle.changeLane(chosen_vid, 1, 1.5)
                            except Exception:
                                pass

                        try:
                            traci.vehicle.slowDown(chosen_vid, float(new_sp), 2.4)
                        except Exception:
                            try:
                                traci.vehicle.setSpeed(chosen_vid, float(new_sp))
                            except Exception:
                                pass

                        try:
                            ids = [v for v in traci.vehicle.getIDList()]
                            members = [v for v in ids if vid_platoon_index.get(v) == chosen_pidx]
      
                            try:
                                members.sort(key=lambda v: traci.vehicle.getPosition(v)[0], reverse=True)
                            except Exception:
                                pass
                            if chosen_vid in members:
                                idx = members.index(chosen_vid)
                                ahead = members[:idx]   
                                behind = members[idx+1:]  
                            else:
                                ahead = [vid_for(chosen_pidx, 0)] if vid_for(chosen_pidx,0) in ids else []
                                behind = [v for v in members if v not in ahead and v != chosen_vid]
      
                            new_idx = _find_free_platoon_index(pids, vid_platoon_index, ids)
     
                            if new_idx == chosen_pidx:
                                new_idx = chosen_pidx + 1 if chosen_pidx + 1 <= max(PLATOON_COUNT-1, chosen_pidx) else chosen_pidx
    
                            for v in ahead:
                                vid_platoon_index[v] = chosen_pidx
                            for v in behind:
                                vid_platoon_index[v] = new_idx
        
                            if behind:
                                first_plate = vid_to_plate.get(behind[0]) or plate_for(new_idx, 0)
                                new_pid = _call_grpc_fn(["rsu_auth_and_join","auth_and_join","join_platoon","join","join_rsu"], first_plate, None)
                                if new_pid is None:
                                    new_pid = rsu_auth_and_join(None, first_plate, pid=None)
    
                                if new_idx not in pids:
                                    pids[new_idx] = None
                                pids[new_idx] = new_pid
                                for v in behind:
                                    vid_to_pid[v] = new_pid

                            vid_platoon_index[chosen_vid] = -1
                            vid_to_pid[chosen_vid] = None

                            # --- NEW: adjust colours for both sides of the split ---
                            try:
                                # colour for vehicles that remain in original platoon (ahead)
                                ahead_color = PLATOON_COLORS[chosen_pidx % len(PLATOON_COLORS)]
                                # colour for vehicles assigned to new platoon (behind)
                                new_color = PLATOON_COLORS[new_idx % len(PLATOON_COLORS)]
                                for v in ahead:
                                    try:
                                        traci.vehicle.setColor(v, ahead_color)
                                    except Exception:
                                        try:
                                            traci.vehicle.setColor(v, list(ahead_color))
                                        except Exception:
                                            pass
                                for v in behind:
                                    try:
                                        traci.vehicle.setColor(v, new_color)
                                    except Exception:
                                        try:
                                            traci.vehicle.setColor(v, list(new_color))
                                        except Exception:
                                            pass
                                # mark them as explicitly coloured so per-step colouring won't override
                                try:
                                    colored.update(ahead)
                                    colored.update(behind)
                                except Exception:
                                    for vv in ahead:
                                        colored.add(vv)
                                    for vv in behind:
                                        colored.add(vv)
                                # set a neutral/leave colour for the leaving vehicle
                                try:
                                    leave_color = (160,160,160,255)
                                    traci.vehicle.setColor(chosen_vid, leave_color)
                                    colored.add(chosen_vid)
                                except Exception:
                                    pass
                            except Exception:
                                pass
                            # --- END NEW color handling ---

                            safe_put(msg_q, f"[LEAVE] step {step}: {chosen_vid} (was {old_sp:.2f} m/s) changed lane->{target_lane} speed->{new_sp:.2f} m/s; split platoon {chosen_pidx} -> kept {len(ahead)} / new {len(behind)} assigned idx {new_idx}")
           
                            try:
                                _call_grpc_fn(["notify_platoon_split", "split_platoon", "platoon_split"], chosen_pidx, new_idx, ahead, behind)
                            except Exception:
                                pass
                        except Exception as e:
                            safe_put(msg_q, f"[LEAVE] platoon split handling failed: {e}")
                        middle_left_done = True
                except Exception as e:
                    safe_put(msg_q, f"[LEAVE] step {step} failed: {e}")

            if merged_done:
                cspeed = LEADER_SPEED_MPS * 0.95
                for vid in present:
                    try:
                        traci.vehicle.slowDown(vid, cspeed, 1.0)
                    except Exception:
                        pass

            try:
                minexp = traci.simulation.getMinExpectedNumber()
                present_now = len(traci.vehicle.getIDList())
                if minexp == 0 and present_now == 0:
                    safe_put(msg_q, "[SUMO] Simulation ended (no expected or present vehicles)")
                    break
            except Exception:
                pass

            step += 1
            time.sleep(SIM_SLEEP)

            if step % 50 == 0:
                try:
                    ids = traci.vehicle.getIDList()
                    leaders = []
                    for p in range(PLATOON_COUNT):
                        lid = vid_for(p, 0)
                        if lid in ids:
                            pos = traci.vehicle.getPosition(lid)
                            leaders.append(f"{lid}={pos[0]:.1f},{pos[1]:.1f}")
                    if leaders:
                        print(f"[SUMO] step {step}/{SIM_STEPS} time={sim_time:.1f}s vehicles={len(ids)}")
                        print(" Leaders: " + " | ".join(leaders))
                except Exception:
                    print(f"[SUMO] step {step}/{SIM_STEPS} time={sim_time:.1f}s")

                for pidx in range(PLATOON_COUNT):
                        dists = []
                        members = [vid_for(pidx, i) for i in range(PLATOON_SIZES[pidx]) if vid_for(pidx, i) in ids]
                
                        members += [v for v in ids if vid_platoon_index.get(v) == pidx and v not in members]

                        try:
                            members.sort(key=lambda v: traci.vehicle.getPosition(v)[0], reverse=True)
                        except Exception:
                            pass
                        for i in range(1, len(members)):
                            try:
                                p_lead = traci.vehicle.getPosition(members[i-1])
                                p_foll = traci.vehicle.getPosition(members[i])
                                dist = math.hypot(p_lead[0]-p_foll[0], p_lead[1]-p_foll[1])
                                dists.append(f"{members[i-1]}->{members[i]}:{dist:.1f}m")
                            except Exception:
                                dists.append(f"{members[i-1]}->{members[i]}:N/A")
                        if not dists:
                            print(f"[PLATOON] p{pidx+1} (members {len(members)}): no consecutive pairs")
                        else:
                            print(f"[PLATOON] p{pidx+1} distances: " + " | ".join(dists))

    finally:
        try:
            traci.close()
        except Exception:
            pass
        safe_put(msg_q, "[SUMO] finished")
        safe_put(msg_q, "__QUIT__")

if __name__ == "__main__":
    main()
