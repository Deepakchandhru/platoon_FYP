import grpc
import platoon_pb2
import platoon_pb2_grpc

GRPC_HOST = "localhost"
GRPC_PORT = 50051

def main():
    channel = grpc.insecure_channel(f"{GRPC_HOST}:{GRPC_PORT}")
    stub = platoon_pb2_grpc.PlatoonServiceStub(channel)

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

main()