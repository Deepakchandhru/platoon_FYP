"""
Verification module for consistency checks
Implements kinematic and obstacle verification logic
"""

import trust.src.config as config
from trust.src.messaging import check_obstacle_exists


class VoteType:
    """Vote types for reputation system"""
    UPVOTE = 'UPVOTE'
    DOWNVOTE = 'DOWNVOTE'
    SEVERE_DOWNVOTE = 'SEVERE_DOWNVOTE'
    NO_VOTE = 'NO_VOTE'


class Verifier:
    """Handles all verification and voting logic"""
    
    def __init__(self):
        self.previous_states = {}  # {veh_id: previous_state}
        self.obstacle_reporters = {}  # {(lane, pos, time): first_reporter_id}
    
    def update_previous_state(self, veh_id, state):
        """Store previous state for position prediction"""
        self.previous_states[veh_id] = {
            'position': state['position'],
            'speed': state['speed'],
            'acceleration': state['acceleration'],
            'timestamp': state['timestamp']
        }
    
    def is_eligible_for_beacon_vote(self, receiver_state, sender_state):
        """
        Check if receiver is eligible to vote on sender's beacon
        
        Args:
            receiver_state: Dict with receiver's position
            sender_state: Dict with sender's position
        
        Returns:
            bool: True if eligible
        """
        distance = abs(receiver_state['position'] - sender_state['position'])
        return distance <= config.BEACON_VERIFICATION_RANGE
    
    def is_eligible_for_obstacle_vote(self, receiver_state, obstacle_position):
        """
        Check if receiver is eligible to vote on obstacle claim
        
        Args:
            receiver_state: Dict with receiver's position
            obstacle_position: Position of claimed obstacle
        
        Returns:
            bool: True if eligible
        """
        distance = abs(receiver_state['position'] - obstacle_position)
        return distance <= config.OBSTACLE_VERIFICATION_RANGE
    
    def verify_beacon(self, message):
        """
        Verify kinematic consistency of beacon message
        
        Args:
            message: BeaconMessage object
        
        Returns:
            str: VoteType (UPVOTE or DOWNVOTE)
        """
        # Check speed bounds
        if not (config.MIN_SPEED <= message.speed <= config.MAX_SPEED):
            return VoteType.DOWNVOTE
        
        # Check acceleration bounds
        if not (config.MIN_ACCEL <= message.acceleration <= config.MAX_ACCEL):
            return VoteType.DOWNVOTE
        
        # Position prediction check (if previous state exists)
        if message.sender_id in self.previous_states:
            prev = self.previous_states[message.sender_id]
            dt = message.timestamp - prev['timestamp']
            
            if dt > 0:  # Avoid division by zero
                # Predicted position using kinematic equation
                predicted_pos = (prev['position'] + 
                               prev['speed'] * dt + 
                               0.5 * prev['acceleration'] * dt * dt)
                
                position_error = abs(predicted_pos - message.position)
                
                if position_error > config.POSITION_PREDICTION_THRESHOLD:
                    return VoteType.DOWNVOTE
        
        return VoteType.UPVOTE
    
    def verify_obstacle(self, message):
        """
        Verify obstacle claim against ground truth
        
        Args:
            message: ObstacleMessage object
        
        Returns:
            str: VoteType (UPVOTE, DOWNVOTE, or SEVERE_DOWNVOTE)
        """
        # Check ground truth
        obstacle_exists = check_obstacle_exists(
            message.lane,
            message.obstacle_position,
            message.timestamp
        )
        
        if message.obstacle_in_lane and not obstacle_exists:
            # False positive - severe penalty
            return VoteType.SEVERE_DOWNVOTE
        elif not message.obstacle_in_lane and obstacle_exists:
            # Missed detection - regular penalty
            return VoteType.DOWNVOTE
        else:
            # Correct report
            return VoteType.UPVOTE
    
    def register_obstacle_reporter(self, message):
        """
        Register the first vehicle to correctly report an obstacle
        
        Args:
            message: ObstacleMessage object
        
        Returns:
            bool: True if this is the first reporter
        """
        # Create unique key for this obstacle report
        obstacle_key = (
            message.lane,
            int(message.obstacle_position / 10) * 10,  # Round to nearest 10m
            int(message.timestamp)  # Round to nearest second
        )
        
        if obstacle_key not in self.obstacle_reporters:
            self.obstacle_reporters[obstacle_key] = message.sender_id
            return True
        
        return False
    
    def process_message(self, receiver_id, message, receiver_state, sender_state):
        """
        Process a message and generate a vote
        
        Args:
            receiver_id: ID of receiving vehicle
            message: BeaconMessage or ObstacleMessage
            receiver_state: Dict with receiver's state
            sender_state: Dict with sender's state
        
        Returns:
            tuple: (vote_type, is_first_obstacle_reporter)
        """
        is_first_reporter = False
        
        if message.msg_type == 'BEACON':
            # Check eligibility
            if not self.is_eligible_for_beacon_vote(receiver_state, sender_state):
                return VoteType.NO_VOTE, False
            
            # Verify beacon
            vote = self.verify_beacon(message)
            
        elif message.msg_type == 'OBSTACLE':
            # Check eligibility
            if not self.is_eligible_for_obstacle_vote(receiver_state, 
                                                      message.obstacle_position):
                return VoteType.NO_VOTE, False
            
            # Verify obstacle
            vote = self.verify_obstacle(message)
            
            # Check if first reporter (only for correct reports)
            if vote == VoteType.UPVOTE and message.obstacle_in_lane:
                is_first_reporter = self.register_obstacle_reporter(message)
        
        else:
            return VoteType.NO_VOTE, False
        
        return vote, is_first_reporter

