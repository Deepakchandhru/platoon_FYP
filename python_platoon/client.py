import grpc
import platoon_pb2
import platoon_pb2_grpc

GRPC_HOST = "localhost"
GRPC_PORT = 50051

def print_header(title):
    print("\n" + "=" * 50)
    print(f"  {title}")
    print("=" * 50)

def print_platoons(stub):
    resp = stub.ListPlatoons(platoon_pb2.ListPlatoonsRequest())
    
    if not resp.platoons:
        print("No active platoons.")
        return
    
    for p in resp.platoons:
        print(f"\nPlatoon [{p.pid}] - {len(p.members)} member(s), speed={p.speed}")
        for m in p.members:
            leader_tag = " [LEADER]" if m.is_leader else ""
            print(f"  Position {m.position}: {m.commitment[:20]}...{leader_tag}")

def get_my_platoon(stub, commitment):
    resp = stub.ListPlatoons(platoon_pb2.ListPlatoonsRequest())
    
    for p in resp.platoons:
        for m in p.members:
            if m.commitment == commitment:
                return p.pid, m.is_leader
    
    return None, False

def main():
    channel = grpc.insecure_channel(f"{GRPC_HOST}:{GRPC_PORT}")
    stub = platoon_pb2_grpc.PlatoonServiceStub(channel)

    print_header("Welcome to ZKP Platoon Client")
    print("This client uses Zero-Knowledge Proofs for authentication.")
    print("Your secrets are NEVER stored on the server.")

    authenticated = False
    commitment = None
    vehicle_secret = None
    manufacturer_signature = None

    while not authenticated:
        print("\n--- Authentication Menu ---")
        print("1. Register new vehicle")
        print("2. Login (ZKP Auth)")
        print("3. Exit")
        
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            print_header("Vehicle Registration")
            vehicle_secret = input("Enter vehicle secret: ").strip()
            manufacturer_signature = input("Enter manufacturer signature: ").strip()

            if not vehicle_secret or not manufacturer_signature:
                print("Error: Both fields are required.")
                continue

            resp = stub.RegisterVehicle(
                platoon_pb2.RegisterRequest(
                    vehicle_secret=vehicle_secret,
                    manufacturer_signature=manufacturer_signature
                )
            )

            print(f"\nStatus: {resp.status}")
            print(f"Commitment: {resp.commitment}")

            if resp.status in ["REGISTERED", "ALREADY_REGISTERED"]:
                commitment = resp.commitment
                print("\nRegistration successful! Now authenticate to continue.")

        elif choice == "2":
            print_header("ZKP Authentication")
            
            if not vehicle_secret:
                vehicle_secret = input("Enter vehicle secret: ").strip()
            if not manufacturer_signature:
                manufacturer_signature = input("Enter manufacturer signature: ").strip()
            
            if not commitment:
                print("\nComputing commitment from secrets...")
                import requests
                try:
                    resp = requests.post(
                        "http://localhost:4000/zkp/commitment",
                        json={
                            "vehicle_secret": vehicle_secret,
                            "manufacturer_signature": manufacturer_signature
                        }
                    )
                    commitment = resp.json()["commitment"]
                    print(f"Commitment: {commitment}")
                except Exception as e:
                    print(f"Error computing commitment: {e}")
                    continue

            capability_score = 80
            trust_token = 80

            print("\nAuthenticating with ZKP (secrets not sent to server)...")

            resp = stub.AuthVehicle(
                platoon_pb2.AuthRequest(
                    commitment=commitment,
                    vehicle_secret=vehicle_secret,
                    manufacturer_signature=manufacturer_signature,
                    capability_score=capability_score,
                    trust_token=trust_token
                )
            )

            print(f"\nAuth Result: {resp.status}")

            if resp.status == "APPROVED":
                authenticated = True
                print("\n✓ Authentication successful!")
            else:
                print("\n✗ Authentication failed. Check your credentials.")
                commitment = None
                vehicle_secret = None
                manufacturer_signature = None

        elif choice == "3":
            print("Goodbye!")
            return
        
        else:
            print("Invalid option.")

    while True:
        my_platoon, is_leader = get_my_platoon(stub, commitment)

        print("\n--- Platoon Menu ---")
        print("1. View all platoons")
        print("2. Join/Create platoon")
        print("3. Leave platoon")
        
        if is_leader:
            print("4. Merge platoon (Leader only)")
            print("5. Logout")
        else:
            print("4. Logout")

        if my_platoon:
            leader_str = " [LEADER]" if is_leader else ""
            print(f"\n[Current: Platoon {my_platoon}{leader_str}]")

        action = input("\nSelect option: ").strip()

        if action == "1":
            print_header("All Platoons")
            print_platoons(stub)

        elif action == "2":
            if my_platoon:
                print(f"\nYou are already in platoon {my_platoon}. Leave first to join another.")
                continue

            print_header("Join/Create Platoon")
            pid = input("Enter Platoon ID to join (leave empty to create new): ").strip()

            resp = stub.JoinPlatoon(
                platoon_pb2.JoinRequest(
                    commitment=commitment,
                    pid=pid
                )
            )

            print(f"\nResult: {'✓' if resp.ok else '✗'}")
            print(f"Platoon ID: {resp.pid}")
            print(f"Message: {resp.message}")

        elif action == "3":
            if not my_platoon:
                print("\nYou are not in any platoon.")
                continue

            print_header(f"Leave Platoon {my_platoon}")
            confirm = input(f"Are you sure you want to leave platoon {my_platoon}? (y/n): ").strip().lower()

            if confirm == "y":
                resp = stub.LeavePlatoon(
                    platoon_pb2.LeaveRequest(commitment=commitment)
                )

                print(f"\nResult: {'✓' if resp.ok else '✗'}")
                print(f"Message: {resp.message}")
            else:
                print("Cancelled.")

        elif action == "4" and is_leader:
            print_header("Merge Platoon")
            print(f"Your platoon: {my_platoon}")
            
            print("\nOther platoons:")
            list_resp = stub.ListPlatoons(platoon_pb2.ListPlatoonsRequest())
            other_platoons = [p.pid for p in list_resp.platoons if p.pid != my_platoon]
            
            if not other_platoons:
                print("No other platoons available to merge.")
                continue
            
            for pid in other_platoons:
                print(f"  - {pid}")

            dst_pid = input("\nEnter destination Platoon ID to merge into: ").strip()

            if not dst_pid:
                print("Cancelled.")
                continue

            resp = stub.MergePlatoon(
                platoon_pb2.MergeRequest(
                    commitment=commitment,
                    src_pid=my_platoon,
                    dst_pid=dst_pid
                )
            )

            print(f"\nResult: {'✓' if resp.ok else '✗'}")
            print(f"Message: {resp.message}")

        elif (action == "4" and not is_leader) or (action == "5" and is_leader):
            print_header("Logout")
            
            if my_platoon:
                confirm = input(f"Leave platoon {my_platoon} before logout? (y/n): ").strip().lower()
                if confirm == "y":
                    stub.LeavePlatoon(
                        platoon_pb2.LeaveRequest(commitment=commitment)
                    )
                    print("Left platoon.")

            print("Goodbye!")
            break

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()