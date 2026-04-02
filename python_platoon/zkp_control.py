import traci
import math
import grpc
import platoon_pb2
import platoon_pb2_grpc
import threading
import queue
import tkinter as tk

# RSU positions (every ~500m in the map area) - all use single server port
RSUS = [
    {"id": "rsu1", "x": 2000, "y": 2000, "port": 50051},
    {"id": "rsu2", "x": 3000, "y": 2000, "port": 50051},
    {"id": "rsu3", "x": 4000, "y": 2000, "port": 50051},
    {"id": "rsu4", "x": 5000, "y": 2000, "port": 50051},
    {"id": "rsu5", "x": 6000, "y": 2000, "port": 50051},
]

msg_q = queue.Queue()

def safe_put(q, s):
    try:
        q.put(s)
    except Exception:
        pass

def overlay_thread(q):
    root = tk.Tk()
    root.title("ZKP Platoon Logs")
    root.geometry("520x360+900+60")
    root.attributes("-topmost", True)
    txt = tk.Text(root, bg="#111", fg="#fff", wrap="word", font=("Consolas",10))
    txt.pack(fill="both", expand=True, padx=6, pady=6)
    def poll():
        try:
            while True:
                msg = q.get_nowait()
                txt.insert(tk.END, msg + "\n")
                txt.see(tk.END)
        except queue.Empty:
            pass
        root.after(200, poll)
    root.after(200, poll)
    root.mainloop()

def get_nearest_rsu(vehicle_x, vehicle_y):
    nearest = min(RSUS, key=lambda rsu: math.sqrt((rsu["x"] - vehicle_x)**2 + (rsu["y"] - vehicle_y)**2))
    return nearest

def authenticate_vehicle(vehicle_id, rsu):
    id = int(vehicle_id.split("_")[-1][3:])  # Extract numeric ID from vehicle ID
    safe_put(msg_q, f"Processing authentication for vehicle {vehicle_id} (ID: {id})")

    channel = grpc.insecure_channel(f"localhost:{rsu['port']}")
    stub = platoon_pb2_grpc.PlatoonServiceStub(channel)
    
    # First, try to register
    try:
        reg_resp = stub.RegisterVehicle(platoon_pb2.RegisterRequest(
            vehicle_secret=str(3000 + id),  # Changed base to 3000
            manufacturer_signature=str(4000 + id)  # Changed base to 4000
        ))
    except grpc.RpcError as e:
        safe_put(msg_q, f"Registration error for {vehicle_id}: {e}")
        return None
    
    if reg_resp.status in ["REGISTERED", "ALREADY_REGISTERED"]:
        # Now authenticate
        try:
            auth_resp = stub.AuthVehicle(platoon_pb2.AuthRequest(
                commitment=reg_resp.commitment,
                vehicle_secret=str(3000 + id),  # Changed base to 3000
                manufacturer_signature=str(4000 + id),  # Changed base to 4000
                capability_score=80,
                trust_token=80
            ))
            if auth_resp.status == "APPROVED":
                return reg_resp.commitment
        except grpc.RpcError as e:
            safe_put(msg_q, f"Authentication error for {vehicle_id}: {e}")
            return None
    return None

sumoCmd = ["sumo-gui", "-c", "zkp_simulation.sumocfg"]

traci.start(sumoCmd)

threading.Thread(target=overlay_thread, args=(msg_q,), daemon=True).start()

# Global gRPC stub
channel = grpc.insecure_channel("localhost:50051")
stub = platoon_pb2_grpc.PlatoonServiceStub(channel)

# Spawn initial vehicles
traci.vehicle.add("zkp_veh1", "zkp_platoon1", "car", depart="0", departLane="0", departSpeed="5")
traci.vehicle.add("zkp_veh2", "zkp_platoon1", "car", depart="0", departLane="1", departSpeed="5")

traci.vehicle.add("zkp_veh3", "zkp_platoon2", "car", depart="0", departLane="0", departSpeed="5")
traci.vehicle.add("zkp_veh4", "zkp_platoon2", "car", depart="0", departLane="1", departSpeed="5")

spawned_join1 = False
spawned_join2 = False
authenticated_vehicles = set()
platoon_pids = {}  # route -> pid
vehicle_platoon = {}  # vehicle_id -> pid
vehicle_commitment = {}  # vehicle_id -> commitment
platoon_colors = {}  # pid -> color
color_list = [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0), (255, 0, 255)]  # Red, Green, Blue, Yellow, Magenta
color_index = 0

step = 0
max_steps = 500

while step < max_steps:
    traci.simulationStep()
    step += 1

    vehicles = traci.vehicle.getIDList()

    # Authenticate vehicles via nearest RSU
    for v in vehicles:
        if v not in authenticated_vehicles:
            pos = traci.vehicle.getPosition(v)
            rsu = get_nearest_rsu(pos[0], pos[1])
            commitment = authenticate_vehicle(v, rsu)
            if commitment:
                authenticated_vehicles.add(v)
                vehicle_commitment[v] = commitment
                safe_put(msg_q, f"Vehicle {v} authenticated via RSU {rsu['id']}")
                
                # After auth, join platoon based on route
                try:
                    route_id = traci.vehicle.getRouteID(v)
                    pid = platoon_pids.get(route_id)
                    if not pid:
                        # Create new platoon
                        join_resp = stub.JoinPlatoon(platoon_pb2.JoinRequest(commitment=commitment, pid=""))
                        if join_resp.ok:
                            pid = join_resp.pid
                            platoon_pids[route_id] = pid
                            if pid not in platoon_colors:
                                platoon_colors[pid] = color_list[color_index % len(color_list)]
                                color_index += 1
                            safe_put(msg_q, f"Vehicle {v} created platoon {pid}")
                        else:
                            safe_put(msg_q, f"Failed to create platoon for {v}: {join_resp.message}")
                    else:
                        # Join existing
                        join_resp = stub.JoinPlatoon(platoon_pb2.JoinRequest(commitment=commitment, pid=pid))
                        if join_resp.ok:
                            safe_put(msg_q, f"Vehicle {v} joined platoon {pid}")
                        else:
                            safe_put(msg_q, f"Failed to join platoon for {v}: {join_resp.message}")
                    if pid:
                        vehicle_platoon[v] = pid
                        traci.vehicle.setColor(v, platoon_colors[pid])
                except grpc.RpcError as e:
                    safe_put(msg_q, f"Platoon join error for {v}: {e}")

    # Spawn joining vehicles at junctions
    if not spawned_join1 and any(traci.vehicle.getRoadID(v) == "1427826037" for v in vehicles):
        for i in range(3):
            veh_id = f"zkp_join1_{i}"
            traci.vehicle.add(veh_id, "zkp_join1", "car", departSpeed="5", departLane="0")
        spawned_join1 = True
        safe_put(msg_q, "Spawned joining vehicles for junction 1")

    if not spawned_join2 and any(traci.vehicle.getRoadID(v) == "1015894852#1" for v in vehicles):
        for i in range(2):
            veh_id = f"zkp_join2_{i}"
            traci.vehicle.add(veh_id, "zkp_join2", "car", departSpeed="5", departLane="0")
        spawned_join2 = True
        safe_put(msg_q, "Spawned joining vehicles for junction 2")

    # At step 200, list platoons
    if step == 200:
        try:
            list_resp = stub.ListPlatoons(platoon_pb2.ListPlatoonsRequest())
            safe_put(msg_q, f"At step {step}, active platoons: {[p.pid for p in list_resp.platoons]}")
        except grpc.RpcError as e:
            safe_put(msg_q, f"List platoons error at step {step}: {e}")

    # At step 400, attempt merge for join1 (placeholder, requires leader commitment)
    if step == 400 and spawned_join1:
        try:
            src_pid = platoon_pids.get("zkp_join1")
            dst_pid = platoon_pids.get("zkp_platoon1")
            if src_pid and dst_pid:
                # For merge, assume leader commitment is the commitment of the first vehicle in dst_pid
                leader_commitment = None
                for veh, pid in vehicle_platoon.items():
                    if pid == dst_pid:
                        leader_commitment = vehicle_commitment[veh]
                        break
                if leader_commitment:
                    merge_resp = stub.MergePlatoons(platoon_pb2.MergeRequest(
                        src_pid=src_pid,
                        dst_pid=dst_pid,
                        leader_commitment=leader_commitment
                    ))
                    if merge_resp.ok:
                        safe_put(msg_q, f"Successfully merged platoon {src_pid} into {dst_pid}")
                        # Update vehicle platoons and colors
                        for veh, pid in vehicle_platoon.items():
                            if pid == src_pid:
                                vehicle_platoon[veh] = dst_pid
                                traci.vehicle.setColor(veh, platoon_colors[dst_pid])
                        # Remove old pid
                        if src_pid in platoon_pids.values():
                            for route, p in platoon_pids.items():
                                if p == src_pid:
                                    del platoon_pids[route]
                                    break
                    else:
                        safe_put(msg_q, f"Failed to merge platoons: {merge_resp.message}")
        except grpc.RpcError as e:
            safe_put(msg_q, f"Merge error at step {step}: {e}")

safe_put(msg_q, f"Simulation completed after {step} steps")

# Leave platoons at the end
for v in authenticated_vehicles:
    try:
        commitment = vehicle_commitment[v]
        leave_resp = stub.LeavePlatoon(platoon_pb2.LeaveRequest(commitment=commitment))
        if leave_resp.ok:
            safe_put(msg_q, f"Vehicle {v} left platoon successfully")
        else:
            safe_put(msg_q, f"Failed to leave platoon for {v}: {leave_resp.message}")
    except grpc.RpcError as e:
        safe_put(msg_q, f"Leave platoon error for {v}: {e}")

traci.close()