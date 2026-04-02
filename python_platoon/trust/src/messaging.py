"""
Message handling module for V2V communication
Defines message types and broadcasting logic
"""

import trust.src.config


class BeaconMessage:
    """High-frequency state message (50 Hz)"""
    
    def __init__(self, sender_id, timestamp, seq_no, lane, position, speed, acceleration):
        self.sender_id = sender_id
        self.timestamp = timestamp
        self.seq_no = seq_no
        self.lane = lane
        self.position = position
        self.speed = speed
        self.acceleration = acceleration
        self.msg_type = 'BEACON'
    
    def to_dict(self):
        return {
            'msg_type': self.msg_type,
            'sender_id': self.sender_id,
            'timestamp': self.timestamp,
            'seq_no': self.seq_no,
            'lane': self.lane,
            'position': self.position,
            'speed': self.speed,
            'acceleration': self.acceleration
        }


class ObstacleMessage:
    """Low-frequency event message (on-demand)"""
    
    def __init__(self, sender_id, timestamp, seq_no, obstacle_in_lane, 
                 obstacle_position, lane):
        self.sender_id = sender_id
        self.timestamp = timestamp
        self.seq_no = seq_no
        self.obstacle_in_lane = obstacle_in_lane
        self.obstacle_position = obstacle_position
        self.lane = lane
        self.msg_type = 'OBSTACLE'
    
    def to_dict(self):
        return {
            'msg_type': self.msg_type,
            'sender_id': self.sender_id,
            'timestamp': self.timestamp,
            'seq_no': self.seq_no,
            'obstacle_in_lane': self.obstacle_in_lane,
            'obstacle_position': self.obstacle_position,
            'lane': self.lane
        }


class MessageBroker:
    """Handles message broadcasting and inbox management"""
    
    def __init__(self):
        self.inbox = {}  # {receiver_id: [messages]}
        self.sequence_numbers = {}  # {sender_id: seq_no}
    
    def initialize_vehicle(self, veh_id):
        """Initialize inbox and sequence number for a vehicle"""
        self.inbox[veh_id] = []
        self.sequence_numbers[veh_id] = 0
    
    def get_next_seq_no(self, sender_id):
        """Get and increment sequence number for sender"""
        seq_no = self.sequence_numbers.get(sender_id, 0)
        self.sequence_numbers[sender_id] = seq_no + 1
        return seq_no
    
    def broadcast_message(self, message, sender_position, all_vehicles):
        """
        Broadcast message to all vehicles within communication range
        
        Args:
            message: BeaconMessage or ObstacleMessage
            sender_position: Position of sender (meters)
            all_vehicles: Dict of {veh_id: vehicle_state}
        """
        for receiver_id, receiver_state in all_vehicles.items():
            # Don't send to self
            if receiver_id == message.sender_id:
                continue
            
            # Check if receiver is within communication range
            distance = abs(receiver_state['position'] - sender_position)
            if distance <= trust.src.config.COMM_RANGE:
                self.inbox[receiver_id].append(message)
    
    def get_inbox(self, veh_id):
        """Get all messages for a vehicle"""
        return self.inbox.get(veh_id, [])
    
    def clear_inbox(self, veh_id):
        """Clear inbox for a vehicle"""
        self.inbox[veh_id] = []
    
    def clear_all_inboxes(self):
        """Clear all inboxes (called after processing)"""
        for veh_id in self.inbox:
            self.inbox[veh_id] = []


def should_send_beacon(current_time, last_beacon_time):
    """
    Determine if it's time to send a beacon message
    
    Args:
        current_time: Current simulation time
        last_beacon_time: Last time beacon was sent
    
    Returns:
        bool: True if beacon should be sent
    """
    if last_beacon_time is None:
        return True
    return (current_time - last_beacon_time) >= trust.src.config.BEACON_INTERVAL


def check_obstacle_exists(lane, position, timestamp):
    """
    Check if an obstacle exists at given location and time (ground truth)
    
    Args:
        lane: Lane ID
        position: Position on lane (meters)
        timestamp: Current simulation time
    
    Returns:
        bool: True if obstacle exists
    """
    for obstacle in trust.src.config.OBSTACLES:
        if (obstacle['lane'] == lane and
            obstacle['pos_start'] <= position <= obstacle['pos_end'] and
            obstacle['t_start'] <= timestamp <= obstacle['t_end']):
            return True
    return False

    