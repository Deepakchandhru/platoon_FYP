"""
Logging module for simulation data
Handles CSV logging and data collection
"""

import os
import csv
import trust.src.config as config

class SimulationLogger:
    """Logs simulation data to CSV file"""
    
    def __init__(self):
        self.log_file_path = os.path.join(config.LOG_DIR, config.LOG_FILE)
        self.log_data = []
        self._ensure_log_directory()
    
    def _ensure_log_directory(self):
        """Create log directory if it doesn't exist"""
        os.makedirs(config.LOG_DIR, exist_ok=True)
    
    def initialize_log_file(self):
        """Create CSV file with headers"""
        headers = [
            'timestamp',
            'vehicle_id',
            'reputation',
            'trust_state',
            'upvotes',
            'downvotes',
            'severe_downvotes',
            'position',
            'speed',
            'acceleration',
            'lane'
        ]
        
        with open(self.log_file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
        
        print(f"[Logger] Log file initialized: {self.log_file_path}")
    
    def log_vehicle_data(self, timestamp, veh_id, reputation_data, vehicle_state, votes):
        """
        Log data for a single vehicle
        
        Args:
            timestamp: Current simulation time
            veh_id: Vehicle ID
            reputation_data: Dict with reputation and trust_state
            vehicle_state: Dict with position, speed, acceleration, lane
            votes: Dict with upvotes, downvotes, severe_downvotes
        """
        row = {
            'timestamp': round(timestamp, 2),
            'vehicle_id': veh_id,
            'reputation': round(reputation_data['reputation'], 2),
            'trust_state': reputation_data['trust_state'],
            'upvotes': votes['upvotes'],
            'downvotes': votes['downvotes'],
            'severe_downvotes': votes['severe_downvotes'],
            'position': round(vehicle_state['position'], 2) if vehicle_state else 0,
            'speed': round(vehicle_state['speed'], 2) if vehicle_state else 0,
            'acceleration': round(vehicle_state['acceleration'], 2) if vehicle_state else 0,
            'lane': vehicle_state['lane'] if vehicle_state else ''
        }
        
        self.log_data.append(row)
    
    def write_to_file(self):
        """Write accumulated log data to CSV file"""
        if not self.log_data:
            return
        
        with open(self.log_file_path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.log_data[0].keys())
            writer.writerows(self.log_data)
        
        self.log_data.clear()
    
    def log_event(self, timestamp, event_type, details):
        """
        Log special events (state transitions, attacks, etc.)
        
        Args:
            timestamp: Current simulation time
            event_type: Type of event (e.g., 'STATE_CHANGE', 'ATTACK_START')
            details: Event details
        """
        print(f"[{round(timestamp, 2)}s] {event_type}: {details}")
    
    def log_reputation_update(self, timestamp, update_info):
        """
        Log reputation update details
        
        Args:
            timestamp: Current simulation time
            update_info: Dict from ReputationManager.update_reputation()
        """
        if update_info['old_state'] != update_info['new_state']:
            self.log_event(
                timestamp,
                'STATE_CHANGE',
                f"{update_info['veh_id']}: {update_info['old_state']} → "
                f"{update_info['new_state']} (R: {update_info['old_reputation']:.1f} → "
                f"{update_info['new_reputation']:.1f})"
            )
        
        if update_info['reputation_change'] != 0:
            print(f"  [{update_info['veh_id']}] R: {update_info['old_reputation']:.1f} → "
                  f"{update_info['new_reputation']:.1f} | "
                  f"Votes: ↑{update_info['upvotes']} ↓{update_info['downvotes']} "
                  f"⚠{update_info['severe_downvotes']} | {update_info['reason']}")
    
    def print_summary(self, all_vehicles, reputation_manager):
        """
        Print final simulation summary
        
        Args:
            all_vehicles: List of all vehicle IDs
            reputation_manager: ReputationManager instance
        """
        print("\n" + "="*70)
        print("SIMULATION SUMMARY")
        print("="*70)
        
        for veh_id in sorted(all_vehicles):
            reputation = reputation_manager.get_reputation(veh_id)
            trust_state = reputation_manager.get_trust_state(veh_id)
            is_malicious = " [MALICIOUS]" if veh_id == config.MALICIOUS_VEHICLE_ID else ""
            
            print(f"{veh_id}{is_malicious:15s} | "
                  f"Reputation: {reputation:5.1f} | "
                  f"State: {trust_state}")
        
        print("="*70)
        print(f"Log file saved: {self.log_file_path}")
        print("="*70 + "\n")

