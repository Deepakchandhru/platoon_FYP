"""
Main simulation loop for CATS (Cooperative Autonomy Trust and Security)
Integrates all modules and runs the SUMO simulation
"""
import config
from messaging import MessageBroker, BeaconMessage, ObstacleMessage, check_obstacle_exists
from verification import Verifier
from reputation import ReputationManager
from sumo_controller import SUMOController
from logger import SimulationLogger
from plotter import SimulationPlotter

class CATSSimulation:
    """Main CATS simulation controller"""
    
    def __init__(self):
        self.message_broker = MessageBroker()
        self.verifier = Verifier()
        self.reputation_manager = ReputationManager()
        self.sumo_controller = SUMOController()
        self.logger = SimulationLogger()
        
        self.initialized_vehicles = set()
        self.window_start_time = 0.0
    
    def initialize_vehicle(self, veh_id):
        """Initialize all systems for a new vehicle"""
        if veh_id not in self.initialized_vehicles:
            self.message_broker.initialize_vehicle(veh_id)
            self.reputation_manager.initialize_vehicle(veh_id)
            self.initialized_vehicles.add(veh_id)
            print(f"[Init] Vehicle {veh_id} initialized")
    
    def broadcast_beacons(self, current_time):
        """Broadcast beacon messages from all vehicles"""
        vehicle_ids = self.sumo_controller.get_vehicle_ids()
        
        for veh_id in vehicle_ids:
            # Check if it's time to send beacon (50 Hz)
            if not self.sumo_controller.should_send_beacon(veh_id, current_time):
                continue
            
            # Get real state from SUMO
            real_state = self.sumo_controller.get_vehicle_state(veh_id)
            if real_state is None:
                continue
            
            # Check for malicious behavior
            malicious_state = self.sumo_controller.get_malicious_behavior(
                veh_id, current_time, real_state
            )
            
            # Use malicious state if applicable, otherwise real state
            state_to_broadcast = malicious_state if malicious_state else real_state
            
            # Create beacon message
            beacon = BeaconMessage(
                sender_id=veh_id,
                timestamp=current_time,
                seq_no=self.message_broker.get_next_seq_no(veh_id),
                lane=state_to_broadcast['lane'],
                position=state_to_broadcast['position'],
                speed=state_to_broadcast['speed'],
                acceleration=state_to_broadcast['acceleration']
            )
            
            # Broadcast to all vehicles in range
            self.message_broker.broadcast_message(
                beacon,
                real_state['position'],  # Use real position for range calculation
                self.sumo_controller.vehicle_states
            )
            
            # Update verifier's previous state (use real state)
            self.verifier.update_previous_state(veh_id, real_state)
    
    def broadcast_obstacle_messages(self, current_time):
        """Broadcast obstacle detection messages"""
        vehicle_ids = self.sumo_controller.get_vehicle_ids()
        
        for veh_id in vehicle_ids:
            state = self.sumo_controller.get_vehicle_state(veh_id)
            if state is None:
                continue
            
            # Check if malicious vehicle should send false obstacle
            if self.sumo_controller.should_send_false_obstacle(veh_id, current_time):
                # Send false obstacle claim
                obstacle_msg = ObstacleMessage(
                    sender_id=veh_id,
                    timestamp=current_time,
                    seq_no=self.message_broker.get_next_seq_no(veh_id),
                    obstacle_in_lane=True,
                    obstacle_position=state['position'] + 50.0,  # Fake obstacle ahead
                    lane=state['lane']
                )
                
                self.message_broker.broadcast_message(
                    obstacle_msg,
                    state['position'],
                    self.sumo_controller.vehicle_states
                )
                
                self.logger.log_event(
                    current_time,
                    'FALSE_OBSTACLE',
                    f"{veh_id} sent false obstacle at {obstacle_msg.obstacle_position:.1f}m"
                )
            
            # Honest vehicles report real obstacles
            else:
                # Check if there's a real obstacle nearby
                for obstacle in config.OBSTACLES:
                    if (obstacle['lane'] == state['lane'] and
                        obstacle['t_start'] <= current_time <= obstacle['t_end']):
                        
                        # Check if vehicle is close to obstacle
                        obstacle_center = (obstacle['pos_start'] + obstacle['pos_end']) / 2
                        distance = abs(state['position'] - obstacle_center)
                        
                        if distance <= 100.0:  # Within detection range
                            obstacle_msg = ObstacleMessage(
                                sender_id=veh_id,
                                timestamp=current_time,
                                seq_no=self.message_broker.get_next_seq_no(veh_id),
                                obstacle_in_lane=True,
                                obstacle_position=obstacle_center,
                                lane=state['lane']
                            )
                            
                            self.message_broker.broadcast_message(
                                obstacle_msg,
                                state['position'],
                                self.sumo_controller.vehicle_states
                            )
                            break  # Only report one obstacle at a time
    
    def process_messages_and_vote(self):
        """Process all messages and generate votes"""
        vehicle_ids = self.sumo_controller.get_vehicle_ids()
        
        for receiver_id in vehicle_ids:
            receiver_state = self.sumo_controller.get_vehicle_state(receiver_id)
            if receiver_state is None:
                continue
            
            # Get all messages for this receiver
            messages = self.message_broker.get_inbox(receiver_id)
            
            # Process each message
            for message in messages:
                sender_state = self.sumo_controller.get_vehicle_state(message.sender_id)
                if sender_state is None:
                    continue
                
                # Generate vote
                vote, is_first_reporter = self.verifier.process_message(
                    receiver_id,
                    message,
                    receiver_state,
                    sender_state
                )
                
                # Add vote to reputation manager
                self.reputation_manager.add_vote(
                    message.sender_id,
                    vote,
                    is_first_reporter
                )
            
            # Clear inbox after processing
            self.message_broker.clear_inbox(receiver_id)

    def update_reputations_and_apply_actions(self, current_time):
        """Update reputations and apply trust-based actions in SUMO"""
        vehicle_ids = list(self.initialized_vehicles)

        for veh_id in vehicle_ids:
            # Update reputation
            update_info = self.reputation_manager.update_reputation(veh_id)

            if update_info:
                # Log reputation update
                self.logger.log_reputation_update(current_time, update_info)

                # Apply trust-based actions in SUMO
                trust_state = self.reputation_manager.get_trust_state(veh_id)
                self.sumo_controller.apply_trust_based_actions(veh_id, trust_state)

        # Clear vote window for next period
        self.reputation_manager.clear_vote_window()

    def log_current_state(self, current_time):
        """Log current state of all vehicles"""
        vehicle_ids = self.sumo_controller.get_vehicle_ids()

        for veh_id in vehicle_ids:
            if veh_id not in self.initialized_vehicles:
                continue

            vehicle_state = self.sumo_controller.get_vehicle_state(veh_id)
            reputation = self.reputation_manager.get_reputation(veh_id)
            trust_state = self.reputation_manager.get_trust_state(veh_id)
            votes = self.reputation_manager.get_votes(veh_id)

            self.logger.log_vehicle_data(
                current_time,
                veh_id,
                {'reputation': reputation, 'trust_state': trust_state},
                vehicle_state,
                votes
            )

        # Write to file periodically
        self.logger.write_to_file()

    def run(self):
        """Main simulation loop"""
        print("\n" + "="*70)
        print("CATS SIMULATION STARTING")
        print("="*70)
        print(f"Duration: {config.SIMULATION_DURATION}s")
        print(f"Step size: {config.SIMULATION_STEP}s")
        print(f"Malicious vehicle: {config.MALICIOUS_VEHICLE_ID}")
        print(f"False obstacle attack: {config.FALSE_OBSTACLE_START_TIME}s - {config.FALSE_OBSTACLE_END_TIME}s")
        print(f"Incorrect beacon attack: {config.INCORRECT_BEACON_START_TIME}s - {config.INCORRECT_BEACON_END_TIME}s")
        print("="*70 + "\n")

        # Initialize logger
        self.logger.initialize_log_file()

        # Start SUMO
        self.sumo_controller.start_sumo(use_gui=config.USE_SUMO_GUI)

        try:
            step = 0
            self.window_start_time = 0.0

            while step * config.SIMULATION_STEP < config.SIMULATION_DURATION:
                # Advance SUMO simulation
                self.sumo_controller.simulation_step()
                current_time = self.sumo_controller.get_current_time()

                # Get all vehicles in simulation
                vehicle_ids = self.sumo_controller.get_vehicle_ids()

                # Initialize new vehicles
                for veh_id in vehicle_ids:
                    self.initialize_vehicle(veh_id)
                    # Update vehicle state from SUMO
                    self.sumo_controller.update_vehicle_state(veh_id, current_time)

                # 1. Broadcast beacon messages (50 Hz)
                self.broadcast_beacons(current_time)

                # 2. Broadcast obstacle messages (on-demand)
                self.broadcast_obstacle_messages(current_time)

                # 3. Process messages and generate votes
                self.process_messages_and_vote()

                # 4. Every 1 second: update reputations and apply actions
                if current_time - self.window_start_time >= config.REPUTATION_UPDATE_WINDOW:
                    print(f"\n--- Time: {current_time:.1f}s ---")
                    self.update_reputations_and_apply_actions(current_time)
                    self.log_current_state(current_time)
                    self.window_start_time = current_time

                step += 1

            # Final logging
            print("\n[Simulation] Completed successfully!")
            self.logger.print_summary(
                list(self.initialized_vehicles),
                self.reputation_manager
            )

        except KeyboardInterrupt:
            print("\n[Simulation] Interrupted by user")

        finally:
            # Close SUMO
            self.sumo_controller.close_sumo()
            print("[Simulation] SUMO closed")


def main():
    """Entry point for CATS simulation"""
    # Create and run simulation
    simulation = CATSSimulation()
    simulation.run()

    # Generate plots
    log_file = f"{config.LOG_DIR}/{config.LOG_FILE}"
    plotter = SimulationPlotter(log_file)
    plotter.generate_all_plots()

    print("\n[Main] Simulation complete! Check logs/ and plots/ directories for results.\n")


if __name__ == "__main__":
    main()

