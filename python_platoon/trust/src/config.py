"""
Configuration file for CATS (Cooperative Autonomy Trust and Security) simulation
Contains all parameters, thresholds, and constants
"""

# ============================================================================
# SIMULATION PARAMETERS
# ============================================================================
SIMULATION_STEP = 1  # seconds (SUMO step size)
SIMULATION_DURATION = 120  # seconds (total simulation time)
REPUTATION_UPDATE_WINDOW = 1.0  # seconds (aggregate votes every 1 second)

# ============================================================================
# COMMUNICATION PARAMETERS
# ============================================================================
COMM_RANGE = 300.0  # meters (V2V communication range)
BEACON_FREQUENCY = 50  # Hz (beacon message rate)
BEACON_INTERVAL = 1.0 / BEACON_FREQUENCY  # seconds between beacons

# ============================================================================
# VERIFICATION PARAMETERS
# ============================================================================
BEACON_VERIFICATION_RANGE = 50.0  # meters (eligibility for beacon verification)
OBSTACLE_VERIFICATION_RANGE = 70.0  # meters (eligibility for obstacle verification)

# Kinematic bounds for consistency checks
MAX_SPEED = 33.3  # m/s (~120 km/h)
MIN_SPEED = 0.0  # m/s
MAX_ACCEL = 2.6  # m/s² (typical vehicle acceleration)
MIN_ACCEL = -4.5  # m/s² (emergency braking)

# Position prediction threshold
POSITION_PREDICTION_THRESHOLD = 5.0  # meters (max deviation allowed)

# ============================================================================
# REPUTATION PARAMETERS
# ============================================================================
INITIAL_REPUTATION = 70.0  # Starting reputation for all vehicles
MIN_REPUTATION = 0.0
MAX_REPUTATION = 100.0

# Reputation thresholds for trust states
TRUSTED_THRESHOLD = 70.0  # R >= 70 → Trusted
UNTRUSTED_THRESHOLD = 40.0  # 40 <= R < 70 → Untrusted
# R < 40 → Banned

# Reputation update rules
UPVOTE_THRESHOLD = 0.7  # 70% upvotes needed for reward
DOWNVOTE_THRESHOLD = 0.3  # 30% downvotes triggers penalty

UPVOTE_REWARD = 1.0  # Reputation increase for good behavior
DOWNVOTE_PENALTY = 5.0  # Reputation decrease for bad behavior
SEVERE_PENALTY = 15.0  # Additional penalty for false obstacles
CORRECT_OBSTACLE_REWARD = 2.0  # Reward for first correct obstacle report

# ============================================================================
# SUMO CONTROL PARAMETERS
# ============================================================================
# Following gap (tau parameter in car-following model)
TRUSTED_TAU = 1.0  # seconds (normal following gap)
UNTRUSTED_TAU = 2.5  # seconds (increased gap for untrusted vehicles)

# Banned vehicle behavior
BANNED_SPEED = 5.0  # m/s (slow speed for banned vehicles)

# ============================================================================
# VEHICLE PARAMETERS
# ============================================================================
NUM_VEHICLES = 10  # Total number of vehicles in platoon
NUM_MALICIOUS = 1  # Number of malicious vehicles
MALICIOUS_VEHICLE_ID = "veh_9"  # Last vehicle in platoon (0-indexed: veh_9)

# ============================================================================
# MALICIOUS BEHAVIOR PARAMETERS
# ============================================================================
# False obstacle attack
FALSE_OBSTACLE_START_TIME = 15.0  # seconds (when to start false obstacle claims)
FALSE_OBSTACLE_END_TIME = 25.0  # seconds (when to stop)
FALSE_OBSTACLE_INTERVAL = 2.0  # seconds (how often to send false obstacle)

# Incorrect beacon attack
INCORRECT_BEACON_START_TIME = 40.0  # seconds
INCORRECT_BEACON_END_TIME = 50.0  # seconds
INCORRECT_POSITION_OFFSET = 20.0  # meters (fake position offset)
INCORRECT_SPEED_MULTIPLIER = 1.5  # multiply real speed by this

# ============================================================================
# GROUND TRUTH OBSTACLES
# ============================================================================
# Format: {'lane': lane_id, 'pos_start': float, 'pos_end': float, 
#          't_start': float, 't_end': float}
OBSTACLES = [
    {
        'lane': 'highway_0',  # Lane ID
        'pos_start': 800.0,  # meters
        'pos_end': 810.0,  # meters
        't_start': 30.0,  # seconds
        't_end': 120.0  # seconds (remains until end)
    }
]

# ============================================================================
# LOGGING PARAMETERS
# ============================================================================
LOG_DIR = "logs"
LOG_FILE = "simulation_log.csv"
PLOT_DIR = "plots"

# ============================================================================
# SUMO FILES
# ============================================================================
SUMO_CONFIG_FILE = "trust/sumo_files/simulation.sumocfg"
NETWORK_FILE = "trust/sumo_files/network.net.xml"
ROUTE_FILE = "trust/sumo_files/routes.rou.xml"

# SUMO GUI settings
USE_SUMO_GUI = True  # Set to False for faster headless simulation
SUMO_DELAY = 100  # milliseconds (GUI delay for visualization)

