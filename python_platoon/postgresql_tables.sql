-- PostgreSQL table creation scripts for CATS reputation system

-- Reputation table (PostgreSQL + final state on blockchain)
CREATE TABLE IF NOT EXISTS reputation (
    vehicle_id TEXT PRIMARY KEY,
    score INTEGER DEFAULT 0,
    trust_state INTEGER DEFAULT 0,  -- 0: TRUSTED, 1: SUSPICIOUS, 2: MALICIOUS
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blockchain_tx_hash TEXT  -- Optional: store tx hash when final state is committed
);

-- Vote history table (PostgreSQL only, for rate limiting)
CREATE TABLE IF NOT EXISTS vote_history (
    id SERIAL PRIMARY KEY,
    voter_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    vote_type TEXT NOT NULL,  -- 'POSITIVE', 'NEGATIVE'
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Flags table (PostgreSQL + optional anchor on blockchain)
CREATE TABLE IF NOT EXISTS flags (
    id SERIAL PRIMARY KEY,
    vehicle_id TEXT NOT NULL,
    flag_type TEXT NOT NULL,
    window_id INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired BOOLEAN DEFAULT FALSE,
    blockchain_tx_hash TEXT  -- Optional: store tx hash when anchored
);

-- Broadcast messages table (PostgreSQL only)
CREATE TABLE IF NOT EXISTS broadcast_messages (
    id SERIAL PRIMARY KEY,
    sender_id TEXT NOT NULL,
    msg_type TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sequence_num INTEGER,
    raw_json TEXT NOT NULL
);

-- Create indices for performance
CREATE INDEX IF NOT EXISTS idx_vote_history_voter_timestamp ON vote_history(voter_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_flags_vehicle ON flags(vehicle_id);
CREATE INDEX IF NOT EXISTS idx_broadcast_sender ON broadcast_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_broadcast_timestamp ON broadcast_messages(timestamp);