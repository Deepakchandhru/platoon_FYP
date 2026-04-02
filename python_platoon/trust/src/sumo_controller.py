"""
SUMO controller module
Handles all interactions with SUMO via TraCI
"""

import traci
import config
from reputation import TrustState


class SUMOController:
    """Manages SUMO simulation and vehicle control"""
    
    def __init__(self):
        self.vehicle_states = {}  # {veh_id: state_dict}
        self.last_beacon_time = {}  # {veh_id: timestamp}
        self.last_obstacle_check = {}  # {veh_id: timestamp}
        self.applied_actions = {}  # {veh_id: action_type}
    
    def start_sumo(self, use_gui=True):
        """
        Start SUMO simulation
        
        Args:
            use_gui: If True, use SUMO-GUI; otherwise use headless SUMO
        """
        sumo_binary = "sumo-gui" if use_gui else "sumo"
        sumo_cmd = [
            sumo_binary,
            "-c", config.SUMO_CONFIG_FILE,
            "--step-length", str(config.SIMULATION_STEP),
            "--delay", str(config.SUMO_DELAY) if use_gui else "0",
            "--start", "true",
            "--quit-on-end", "true"
        ]
        traci.start(sumo_cmd)
    
    def close_sumo(self):
        """Close SUMO simulation"""
        traci.close()
    
    def simulation_step(self):
        """Advance SUMO simulation by one step"""
        traci.simulationStep()
    
    def get_current_time(self):
        """Get current simulation time"""
        return traci.simulation.getTime()
    
    def get_vehicle_ids(self):
        """Get list of all vehicle IDs currently in simulation"""
        return traci.vehicle.getIDList()
    
    def update_vehicle_state(self, veh_id, current_time):
        """
        Read and update vehicle state from SUMO
        
        Args:
            veh_id: Vehicle ID
            current_time: Current simulation time
        
        Returns:
            dict: Vehicle state
        """
        try:
            position = traci.vehicle.getLanePosition(veh_id)
            speed = traci.vehicle.getSpeed(veh_id)
            acceleration = traci.vehicle.getAcceleration(veh_id)
            lane = traci.vehicle.getLaneID(veh_id)
            
            state = {
                'position': position,
                'speed': speed,
                'acceleration': acceleration,
                'lane': lane,
                'timestamp': current_time
            }
            
            self.vehicle_states[veh_id] = state
            return state
            
        except traci.exceptions.TraCIException:
            # Vehicle not in simulation yet or already removed
            return None
    
    def get_vehicle_state(self, veh_id):
        """Get cached vehicle state"""
        return self.vehicle_states.get(veh_id)
    
    def should_send_beacon(self, veh_id, current_time):
        """
        Check if vehicle should send beacon at current time
        
        Args:
            veh_id: Vehicle ID
            current_time: Current simulation time
        
        Returns:
            bool: True if beacon should be sent
        """
        last_time = self.last_beacon_time.get(veh_id)
        if last_time is None:
            self.last_beacon_time[veh_id] = current_time
            return True
        
        if (current_time - last_time) >= config.BEACON_INTERVAL:
            self.last_beacon_time[veh_id] = current_time
            return True
        
        return False
    
    def apply_trust_based_actions(self, veh_id, trust_state):
        """
        Apply SUMO control actions based on trust state
        
        Args:
            veh_id: Vehicle ID
            trust_state: Current trust state (Trusted/Untrusted/Banned)
        """
        # Skip if already applied this action
        if self.applied_actions.get(veh_id) == trust_state:
            return
        
        try:
            if trust_state == TrustState.TRUSTED:
                # Normal behavior - reset to default
                traci.vehicle.setTau(veh_id, config.TRUSTED_TAU)
                traci.vehicle.setSpeedMode(veh_id, 31)  # Default speed mode
                self.applied_actions[veh_id] = TrustState.TRUSTED
                
            elif trust_state == TrustState.UNTRUSTED:
                # Increase following gap (monitor mode)
                traci.vehicle.setTau(veh_id, config.UNTRUSTED_TAU)
                self.applied_actions[veh_id] = TrustState.UNTRUSTED
                
            elif trust_state == TrustState.BANNED:
                # Keep in simulation but remove from cooperative logic
                # Slow down the vehicle
                traci.vehicle.setSpeed(veh_id, config.BANNED_SPEED)
                # Increase gap significantly
                traci.vehicle.setTau(veh_id, 5.0)
                self.applied_actions[veh_id] = TrustState.BANNED
                
        except traci.exceptions.TraCIException:
            # Vehicle not in simulation
            pass
    
    def get_malicious_behavior(self, veh_id, current_time, real_state):
        """
        Generate malicious behavior for designated malicious vehicle
        
        Args:
            veh_id: Vehicle ID
            current_time: Current simulation time
            real_state: Real vehicle state from SUMO
        
        Returns:
            dict: Modified state for malicious behavior, or None for honest behavior
        """
        if veh_id != config.MALICIOUS_VEHICLE_ID:
            return None
        
        malicious_state = None
        
        # Incorrect beacon attack
        if (config.INCORRECT_BEACON_START_TIME <= current_time <= 
            config.INCORRECT_BEACON_END_TIME):
            malicious_state = real_state.copy()
            malicious_state['position'] += config.INCORRECT_POSITION_OFFSET
            malicious_state['speed'] *= config.INCORRECT_SPEED_MULTIPLIER
        
        return malicious_state
    
    def should_send_false_obstacle(self, veh_id, current_time):
        """
        Check if malicious vehicle should send false obstacle message
        
        Args:
            veh_id: Vehicle ID
            current_time: Current simulation time
        
        Returns:
            bool: True if false obstacle should be sent
        """
        if veh_id != config.MALICIOUS_VEHICLE_ID:
            return False
        
        if not (config.FALSE_OBSTACLE_START_TIME <= current_time <= 
                config.FALSE_OBSTACLE_END_TIME):
            return False
        
        # Send false obstacle at intervals
        last_check = self.last_obstacle_check.get(veh_id, 0)
        if (current_time - last_check) >= config.FALSE_OBSTACLE_INTERVAL:
            self.last_obstacle_check[veh_id] = current_time
            return True
        
        return False

