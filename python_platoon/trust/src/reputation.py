"""
Reputation management module
Handles reputation scores, trust states, and vote aggregation
"""

import trust.src.config as config
from trust.src.verification import VoteType


class TrustState:
    """Trust state definitions"""
    TRUSTED = 'Trusted'
    UNTRUSTED = 'Untrusted'
    BANNED = 'Banned'


class ReputationManager:
    """Manages reputation scores and trust states for all vehicles"""
    
    def __init__(self):
        self.reputation = {}  # {veh_id: reputation_score}
        self.trust_state = {}  # {veh_id: trust_state}
        self.votes_window = {}  # {target_veh_id: {upvotes, downvotes, severe_downvotes}}
        self.first_obstacle_reporters = set()  # Track first reporters for rewards
    
    def initialize_vehicle(self, veh_id):
        """Initialize reputation and trust state for a vehicle"""
        self.reputation[veh_id] = config.INITIAL_REPUTATION
        self.trust_state[veh_id] = self._get_trust_state(config.INITIAL_REPUTATION)
        self.votes_window[veh_id] = {
            'upvotes': 0,
            'downvotes': 0,
            'severe_downvotes': 0
        }
    
    def _get_trust_state(self, reputation_score):
        """
        Determine trust state based on reputation score
        
        Args:
            reputation_score: Current reputation value
        
        Returns:
            str: TrustState value
        """
        if reputation_score >= config.TRUSTED_THRESHOLD:
            return TrustState.TRUSTED
        elif reputation_score >= config.UNTRUSTED_THRESHOLD:
            return TrustState.UNTRUSTED
        else:
            return TrustState.BANNED
    
    def add_vote(self, target_veh_id, vote_type, is_first_obstacle_reporter=False):
        """
        Add a vote to the current window
        
        Args:
            target_veh_id: Vehicle being voted on
            vote_type: VoteType (UPVOTE, DOWNVOTE, SEVERE_DOWNVOTE, NO_VOTE)
            is_first_obstacle_reporter: True if first to report correct obstacle
        """
        if vote_type == VoteType.NO_VOTE:
            return
        
        if target_veh_id not in self.votes_window:
            self.votes_window[target_veh_id] = {
                'upvotes': 0,
                'downvotes': 0,
                'severe_downvotes': 0
            }
        
        if vote_type == VoteType.UPVOTE:
            self.votes_window[target_veh_id]['upvotes'] += 1
        elif vote_type == VoteType.DOWNVOTE:
            self.votes_window[target_veh_id]['downvotes'] += 1
        elif vote_type == VoteType.SEVERE_DOWNVOTE:
            self.votes_window[target_veh_id]['severe_downvotes'] += 1
            self.votes_window[target_veh_id]['downvotes'] += 1  # Also count as regular downvote
        
        # Track first obstacle reporters for bonus reward
        if is_first_obstacle_reporter:
            self.first_obstacle_reporters.add(target_veh_id)
    
    def update_reputation(self, veh_id):
        """
        Update reputation based on votes in current window
        
        Args:
            veh_id: Vehicle ID to update
        
        Returns:
            dict: Update details {old_rep, new_rep, old_state, new_state, reason}
        """
        if veh_id not in self.votes_window:
            return None
        
        votes = self.votes_window[veh_id]
        old_reputation = self.reputation[veh_id]
        old_state = self.trust_state[veh_id]
        
        total_votes = votes['upvotes'] + votes['downvotes']
        reputation_change = 0
        reason = []
        
        # Apply voting-based updates
        if total_votes > 0:
            upvote_ratio = votes['upvotes'] / total_votes
            downvote_ratio = votes['downvotes'] / total_votes
            
            if upvote_ratio >= config.UPVOTE_THRESHOLD:
                reputation_change += config.UPVOTE_REWARD
                reason.append(f"+{config.UPVOTE_REWARD} (good behavior)")
            elif downvote_ratio >= config.DOWNVOTE_THRESHOLD:
                reputation_change -= config.DOWNVOTE_PENALTY
                reason.append(f"-{config.DOWNVOTE_PENALTY} (bad behavior)")
        
        # Apply severe penalty for false obstacles
        if votes['severe_downvotes'] >= 1:
            reputation_change -= config.SEVERE_PENALTY
            reason.append(f"-{config.SEVERE_PENALTY} (false obstacle)")
        
        # Apply bonus for first correct obstacle report
        if veh_id in self.first_obstacle_reporters:
            reputation_change += config.CORRECT_OBSTACLE_REWARD
            reason.append(f"+{config.CORRECT_OBSTACLE_REWARD} (first obstacle report)")
        
        # Update reputation with clamping
        new_reputation = old_reputation + reputation_change
        new_reputation = max(config.MIN_REPUTATION, 
                           min(config.MAX_REPUTATION, new_reputation))
        
        self.reputation[veh_id] = new_reputation
        
        # Update trust state
        new_state = self._get_trust_state(new_reputation)
        self.trust_state[veh_id] = new_state
        
        return {
            'veh_id': veh_id,
            'old_reputation': old_reputation,
            'new_reputation': new_reputation,
            'old_state': old_state,
            'new_state': new_state,
            'reputation_change': reputation_change,
            'reason': ', '.join(reason) if reason else 'no change',
            'upvotes': votes['upvotes'],
            'downvotes': votes['downvotes'],
            'severe_downvotes': votes['severe_downvotes']
        }
    
    def clear_vote_window(self):
        """Clear all votes for the next window"""
        for veh_id in self.votes_window:
            self.votes_window[veh_id] = {
                'upvotes': 0,
                'downvotes': 0,
                'severe_downvotes': 0
            }
        self.first_obstacle_reporters.clear()
    
    def get_reputation(self, veh_id):
        """Get current reputation score"""
        return self.reputation.get(veh_id, config.INITIAL_REPUTATION)
    
    def get_trust_state(self, veh_id):
        """Get current trust state"""
        return self.trust_state.get(veh_id, TrustState.TRUSTED)
    
    def get_votes(self, veh_id):
        """Get current vote counts"""
        return self.votes_window.get(veh_id, {
            'upvotes': 0,
            'downvotes': 0,
            'severe_downvotes': 0
        })

