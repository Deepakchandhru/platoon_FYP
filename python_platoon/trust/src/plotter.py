"""
Plotting module for visualization
Generates plots from simulation log data
"""

import os
import pandas as pd
import matplotlib.pyplot as plt
import config


class SimulationPlotter:
    """Creates visualizations from simulation data"""
    
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.data = None
        self._ensure_plot_directory()
    
    def _ensure_plot_directory(self):
        """Create plot directory if it doesn't exist"""
        os.makedirs(config.PLOT_DIR, exist_ok=True)
    
    def load_data(self):
        """Load data from CSV log file"""
        try:
            self.data = pd.read_csv(self.log_file_path)
            print(f"[Plotter] Loaded {len(self.data)} rows from {self.log_file_path}")
            return True
        except FileNotFoundError:
            print(f"[Plotter] Error: Log file not found: {self.log_file_path}")
            return False
    
    def plot_reputation_over_time(self):
        """Plot reputation scores over time for all vehicles"""
        if self.data is None:
            return
        
        plt.figure(figsize=(14, 8))
        
        # Get unique vehicle IDs
        vehicle_ids = self.data['vehicle_id'].unique()
        
        # Plot each vehicle
        for veh_id in sorted(vehicle_ids):
            veh_data = self.data[self.data['vehicle_id'] == veh_id]
            
            # Different style for malicious vehicle
            if veh_id == config.MALICIOUS_VEHICLE_ID:
                plt.plot(veh_data['timestamp'], veh_data['reputation'], 
                        label=f'{veh_id} (Malicious)', linewidth=2.5, 
                        color='red', linestyle='--', marker='o', markersize=3)
            else:
                plt.plot(veh_data['timestamp'], veh_data['reputation'], 
                        label=veh_id, linewidth=1.5, alpha=0.7)
        
        # Add threshold lines
        plt.axhline(y=config.TRUSTED_THRESHOLD, color='green', linestyle=':', 
                   linewidth=2, label='Trusted Threshold (70)', alpha=0.5)
        plt.axhline(y=config.UNTRUSTED_THRESHOLD, color='orange', linestyle=':', 
                   linewidth=2, label='Untrusted Threshold (40)', alpha=0.5)
        
        # Add attack period shading
        plt.axvspan(config.FALSE_OBSTACLE_START_TIME, config.FALSE_OBSTACLE_END_TIME, 
                   alpha=0.2, color='red', label='False Obstacle Attack')
        plt.axvspan(config.INCORRECT_BEACON_START_TIME, config.INCORRECT_BEACON_END_TIME, 
                   alpha=0.2, color='orange', label='Incorrect Beacon Attack')
        
        plt.xlabel('Time (seconds)', fontsize=12)
        plt.ylabel('Reputation Score', fontsize=12)
        plt.title('Vehicle Reputation Over Time (CATS System)', fontsize=14, fontweight='bold')
        plt.legend(loc='best', fontsize=9, ncol=2)
        plt.grid(True, alpha=0.3)
        plt.ylim(-5, 105)
        
        plot_path = os.path.join(config.PLOT_DIR, 'reputation_over_time.png')
        plt.tight_layout()
        plt.savefig(plot_path, dpi=300)
        print(f"[Plotter] Saved: {plot_path}")
        plt.close()
    
    def plot_trust_state_timeline(self):
        """Plot trust state changes over time"""
        if self.data is None:
            return
        
        plt.figure(figsize=(14, 6))
        
        # Map trust states to numeric values
        state_map = {'Trusted': 2, 'Untrusted': 1, 'Banned': 0}
        
        vehicle_ids = sorted(self.data['vehicle_id'].unique())
        
        for idx, veh_id in enumerate(vehicle_ids):
            veh_data = self.data[self.data['vehicle_id'] == veh_id]
            states = veh_data['trust_state'].map(state_map)
            
            if veh_id == config.MALICIOUS_VEHICLE_ID:
                plt.plot(veh_data['timestamp'], states + idx*3, 
                        label=f'{veh_id} (Malicious)', linewidth=2, 
                        color='red', marker='s', markersize=2)
            else:
                plt.plot(veh_data['timestamp'], states + idx*3, 
                        label=veh_id, linewidth=1.5, alpha=0.7)
        
        plt.xlabel('Time (seconds)', fontsize=12)
        plt.ylabel('Trust State', fontsize=12)
        plt.title('Trust State Timeline', fontsize=14, fontweight='bold')
        plt.legend(loc='best', fontsize=9, ncol=2)
        plt.grid(True, alpha=0.3)
        
        plot_path = os.path.join(config.PLOT_DIR, 'trust_state_timeline.png')
        plt.tight_layout()
        plt.savefig(plot_path, dpi=300)
        print(f"[Plotter] Saved: {plot_path}")
        plt.close()
    
    def plot_vote_distribution(self):
        """Plot vote distribution for each vehicle"""
        if self.data is None:
            return
        
        # Aggregate votes per vehicle
        vote_summary = self.data.groupby('vehicle_id').agg({
            'upvotes': 'sum',
            'downvotes': 'sum',
            'severe_downvotes': 'sum'
        }).reset_index()
        
        vehicle_ids = sorted(vote_summary['vehicle_id'].unique())
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        x = range(len(vehicle_ids))
        width = 0.25
        
        upvotes = [vote_summary[vote_summary['vehicle_id'] == v]['upvotes'].values[0] 
                  for v in vehicle_ids]
        downvotes = [vote_summary[vote_summary['vehicle_id'] == v]['downvotes'].values[0] 
                    for v in vehicle_ids]
        severe = [vote_summary[vote_summary['vehicle_id'] == v]['severe_downvotes'].values[0] 
                 for v in vehicle_ids]
        
        ax.bar([i - width for i in x], upvotes, width, label='Upvotes', color='green', alpha=0.7)
        ax.bar(x, downvotes, width, label='Downvotes', color='orange', alpha=0.7)
        ax.bar([i + width for i in x], severe, width, label='Severe Downvotes', color='red', alpha=0.7)
        
        ax.set_xlabel('Vehicle ID', fontsize=12)
        ax.set_ylabel('Vote Count', fontsize=12)
        ax.set_title('Total Vote Distribution per Vehicle', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(vehicle_ids, rotation=45, ha='right')
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')
        
        plot_path = os.path.join(config.PLOT_DIR, 'vote_distribution.png')
        plt.tight_layout()
        plt.savefig(plot_path, dpi=300)
        print(f"[Plotter] Saved: {plot_path}")
        plt.close()
    
    def generate_all_plots(self):
        """Generate all visualization plots"""
        if not self.load_data():
            return
        
        print("\n[Plotter] Generating plots...")
        self.plot_reputation_over_time()
        self.plot_trust_state_timeline()
        self.plot_vote_distribution()
        print("[Plotter] All plots generated successfully!\n")

