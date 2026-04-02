"""
sumo_zkp.py  —  Platoon Simulation with ZKP Auth + CATS Trust + Blockchain
================================================================================
Integrates:
  1. sumo_zkp.py  — ZKP vehicle auth, platoon join/merge/leave/split, RSU ops,
                    bully leader election, SUMO TraCI control loop
  2. trust/src/*  — CATS (Cooperative Autonomy Trust & Security):
                    V2V beacon/obstacle messaging, kinematic verification,
                    vote-based reputation scoring, trust-state enforcement,
                    CSV logging, matplotlib visualisation
  3. Blockchain   — Vehicle initial trust score (80) set in VehicleTrust.sol at
                    login; ongoing reputation + trust-state written to CATS.sol;
                    vote history stored in PostgreSQL; CSV log preserved
================================================================================
Blockchain layout
  • VehicleTrust.sol  — maps vehicleID (string) → trustScore (uint) — used for
                        initial trust score (80) at vehicle login
  • CATS.sol          — stores per-commitment reputation, votes, flags on-chain
DB layout (PostgreSQL, schema auto-created at startup)
  • vehicle_votes       — every individual vote cast during simulation
  • reputation_history  — reputation delta per vehicle per 1-second window
"""

# ============================================================
# STANDARD LIBRARY IMPORTS
# ============================================================
import os
import time
import math
import shutil
import threading
import queue
import re
import random
import csv
import xml.etree.ElementTree as ET
from typing import Dict, Optional, List, Tuple
import hashlib
import hmac
import secrets as _sec_module


# ============================================================
#  CATS TRUST MODULE — CONFIGURATION
# ============================================================

CATS_SIMULATION_STEP          = 0.1
CATS_SIMULATION_DURATION      = 270
CATS_REPUTATION_UPDATE_WINDOW = 1.0

CATS_COMM_RANGE       = 300.0
CATS_BEACON_FREQUENCY = 50
CATS_BEACON_INTERVAL  = 1.0 / CATS_BEACON_FREQUENCY

CATS_BEACON_VERIFICATION_RANGE   = 50.0
CATS_OBSTACLE_VERIFICATION_RANGE = 70.0

CATS_MAX_SPEED =  33.3
CATS_MIN_SPEED =   0.0
CATS_MAX_ACCEL =   2.6
CATS_MIN_ACCEL =  -4.5
CATS_POSITION_PREDICTION_THRESHOLD = 5.0

# Blockchain sets this to 80 at login; this is the offline fallback only
CATS_INITIAL_REPUTATION  = 70.0
CATS_BLOCKCHAIN_INIT_SCORE = 80.0   # score stored on-chain at vehicle login

CATS_MIN_REPUTATION      =   0.0
CATS_MAX_REPUTATION      = 100.0
CATS_TRUSTED_THRESHOLD   =  70.0
CATS_UNTRUSTED_THRESHOLD =  40.0
CATS_UPVOTE_THRESHOLD    =   0.7
CATS_DOWNVOTE_THRESHOLD  =   0.3
CATS_UPVOTE_REWARD       =   1.0
CATS_DOWNVOTE_PENALTY    =   5.0
CATS_SEVERE_PENALTY      =  15.0
CATS_CORRECT_OBSTACLE_REWARD = 2.0

CATS_TRUSTED_TAU   = 1.0
CATS_UNTRUSTED_TAU = 2.5
CATS_BANNED_SPEED  = 5.0

CATS_MALICIOUS_VEHICLE_ID        = "v_p1_6"
CATS_FALSE_OBSTACLE_START_TIME   =  30.0
CATS_FALSE_OBSTACLE_END_TIME     =  60.0
CATS_FALSE_OBSTACLE_INTERVAL     =   2.0
CATS_INCORRECT_BEACON_START_TIME =  80.0
CATS_INCORRECT_BEACON_END_TIME   = 110.0
CATS_INCORRECT_POSITION_OFFSET   =  20.0
CATS_INCORRECT_SPEED_MULTIPLIER  =   1.5

CATS_OBSTACLES = [
    {
        'lane':      'main_0_0',
        'pos_start':  400.0,
        'pos_end':    410.0,
        't_start':     60.0,
        't_end':      270.0,
    }
]

CATS_LOG_DIR  = "logs"
CATS_LOG_FILE = "simulation_log.csv"
CATS_PLOT_DIR = "plots"

# ============================================================
#  BLOCKCHAIN CONFIGURATION
# ============================================================

BLOCKCHAIN_PROVIDER             = "http://127.0.0.1:7545"
BLOCKCHAIN_GAS_LIMIT            = 3_000_000
# Set these env-vars to reuse already-deployed contracts across runs.
# If empty, both contracts are deployed fresh at startup.
ENV_CATS_ADDRESS         = os.environ.get("CATS_CONTRACT_ADDRESS",         "")
ENV_VEHICLE_TRUST_ADDRESS= os.environ.get("VEHICLE_TRUST_CONTRACT_ADDRESS","")

# Solidity source inlined so no external .sol files are required
_VEHICLE_TRUST_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract VehicleTrust {
    mapping(string => uint) public trustScore;
    function setTrustScore(string memory vehicleID, uint score) public {
        trustScore[vehicleID] = score;
    }
    function getTrustScore(string memory vehicleID) public view returns (uint) {
        return trustScore[vehicleID];
    }
}
"""

_CATS_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract CATS {
    bytes32[] public commitments;
    struct VehicleData { uint256 capabilityScore; uint256 trustToken; }
    mapping(bytes32 => VehicleData) public vehicleData;

    struct Reputation {
        int256 score;
        uint8  trustState;   // 0 Trusted | 1 Untrusted | 2 Banned
        uint256 lastUpdated;
    }
    struct Vote {
        address voter;
        bytes32 targetCommitment;
        uint8   voteType;          // 0 positive | 1 negative
        uint256 timestamp;
        string  reason;
    }
    struct Flag {
        bytes32 vehicleCommitment;
        string  flagType;
        uint256 windowId;
        uint256 timestamp;
    }

    mapping(bytes32 => Reputation) public reputations;
    Vote[] public votes;
    Flag[] public flags;

    event ReputationUpdated(bytes32 indexed commitment, int256 score, uint8 trustState);
    event VoteRecorded(address indexed voter, bytes32 indexed target, uint8 voteType);
    event FlagAdded(bytes32 indexed vehicle, string flagType, uint256 windowId);

    function addCommitment(bytes32 _c, uint256 _cap, uint256 _trust) public {
        vehicleData[_c] = VehicleData(_cap, _trust);
        commitments.push(_c);
    }
    function getCommitments() public view returns (bytes32[] memory) { return commitments; }
    function getCommitmentCount() public view returns (uint256) { return commitments.length; }
    function getVehicleData(bytes32 _c) public view returns (uint256, uint256) {
        return (vehicleData[_c].capabilityScore, vehicleData[_c].trustToken);
    }
    function updateReputation(bytes32 _c, int256 _score, uint8 _state) public {
        reputations[_c] = Reputation(_score, _state, block.timestamp);
        emit ReputationUpdated(_c, _score, _state);
    }
    function getReputation(bytes32 _c) public view returns (int256, uint8, uint256) {
        Reputation memory r = reputations[_c];
        return (r.score, r.trustState, r.lastUpdated);
    }
    function recordVote(bytes32 _target, uint8 _type, string memory _reason) public {
        votes.push(Vote(msg.sender, _target, _type, block.timestamp, _reason));
        emit VoteRecorded(msg.sender, _target, _type);
    }
    function getVoteCount() public view returns (uint256) { return votes.length; }
    function getVote(uint256 i) public view returns (address, bytes32, uint8, uint256, string memory) {
        Vote memory v = votes[i];
        return (v.voter, v.targetCommitment, v.voteType, v.timestamp, v.reason);
    }
    function addFlag(bytes32 _c, string memory _type, uint256 _window) public {
        flags.push(Flag(_c, _type, _window, block.timestamp));
        emit FlagAdded(_c, _type, _window);
    }
    function getFlagCount() public view returns (uint256) { return flags.length; }
    function getFlag(uint256 i) public view returns (bytes32, string memory, uint256, uint256) {
        Flag memory f = flags[i];
        return (f.vehicleCommitment, f.flagType, f.windowId, f.timestamp);
    }
}
"""

# ============================================================
#  BLOCKCHAIN MANAGER
# ============================================================

# Paper Security Module header
# ============================================================
# PAPER SECURITY MODULE  Khan et al. IEEE TITS 2025
# ============================================================

CA_KEY_ROTATION_INTERVAL  = 60.0
CA_PROOF_TIMESTAMP_WINDOW = 10.0
DDOS_MSG_RATE_LIMIT       = 5
PLATOON_VMAX = 20.0
PLATOON_VMIN =  2.0
SECURITY_LOG_FILE = "logs/security_events.csv"

class CAKeyPair:
    # Paper Algorithm 1: PKCA=KeyGen(IdCA,TS), SKCA=KeyGen(IdCA,TS)
    # pk=public (broadcast to all), sk=private (CA only)
    # ts=timestamp, used to detect stale-key impersonation attacks
    def __init__(self, pk, sk, ts, salt):
        self.pk=pk; self.sk=sk; self.ts=ts; self.salt=salt

class VehicleRegistration:
    # Paper Algorithm 2: FIdv=Hash(Salt(Idv)), SKv, PKv, CertCA
    # PRIVACY: real_id stored ONLY in CA private memory, never on-chain
    def __init__(self, real_id, fake_id, pk_v, sk_v, cert,
                 salt_v, registered_at, pk_ca_used):
        self.real_id=real_id; self.fake_id=fake_id; self.pk_v=pk_v
        self.sk_v=sk_v; self.cert=cert; self.salt_v=salt_v
        self.registered_at=registered_at; self.pk_ca_used=pk_ca_used

class ZKProof:
    # Paper Algorithm 3: sm=Hash(Salt(Sig_SKv,T)) Eq17
    #   x=(sm,PK_CA) Eq18, w=(SKv,PKv) Eq19, Proof=(Pk,x,w) Eq20
    # ZK construction: proof=Hash(Pk||x||Hash(w))
    # Verifier checks Hash(w) without seeing w -> zero-knowledge
    def __init__(self, sm, x, proof, timestamp, pk_ca):
        self.sm=sm; self.x=x; self.proof=proof
        self.timestamp=timestamp; self.pk_ca=pk_ca

class VerificationResult:
    # Paper Algorithm 4 output: True/False single bit
    # PL receives ONLY accepted bit, never reason (ZK + Goal 2)
    # proof_gen_ms / verify_ms -> Section VII Fig 3 and 4 data
    def __init__(self, accepted, reason, proof_gen_ms=0.0, verify_ms=0.0):
        self.accepted=accepted; self.reason=reason
        self.proof_gen_ms=proof_gen_ms; self.verify_ms=verify_ms

class PlatoonFormationTiming:
    # Paper Section V.A: formation time for one vehicle joining
    # situation 1=speed_up(Eq13) 2=slow_down(Eq14)
    #           3=standing(Eq15)  4=cooperative(Eq16)
    # auth_time_T = zk-SNARK proof gen time (key parameter in all equations)
    def __init__(self, vehicle_id, situation, v_i, v_1, a_i, a_1,
                 distance_D, auth_time_T, formation_time, position_offset):
        self.vehicle_id=vehicle_id; self.situation=situation
        self.v_i=v_i; self.v_1=v_1; self.a_i=a_i; self.a_1=a_1
        self.distance_D=distance_D; self.auth_time_T=auth_time_T
        self.formation_time=formation_time; self.position_offset=position_offset

class CertificationAuthority:
    # Paper Section IV.D + Algorithm 1 + Design Goals 1 and 2
    # ONLY trusted entity. Blockchain readable ONLY by CA.
    # Pk=proving key (public), Vk=verification key (CA only)
    # SK_CA=private, never shared. PK_CA=public, broadcast to all.
    # Roles: system setup, key rotation, Alg2 registration,
    #        Alg4 proof verification, Blockchain result storage.
    _MASTER_SECRET = None  # set in __init__ via secrets.token_bytes
    def __init__(self):
        import secrets as _sec
        CertificationAuthority._MASTER_SECRET = _sec.token_bytes(32)
        self.Pk=""; self.Vk=""; self.id_ca="CA_ROOT"
        self.current_key=None
        self.key_history={}
        self._registry={}
        self._witness_hashes={}
        self._auth_status={}
        self.proof_gen_times=[]
        self.proof_verify_times=[]
        self._last_rotation_sim_time=0.0
        self._setup()

    def _setup(self):
        # Algorithm 1: (Pk,Vk)=KeyGen(R,C)
        # Pk distributed to all provers; Vk kept ONLY at CA
        self.Pk=hmac.new(self._MASTER_SECRET,
            ("proving_key_"+self.id_ca).encode(),hashlib.sha256).hexdigest()
        self.Vk=hmac.new(self._MASTER_SECRET,
            ("verification_key_"+self.id_ca).encode(),hashlib.sha256).hexdigest()
        self.current_key=self._gen_kp(0.0)
        print("[CA] Setup Pk=%s... PK_CA=%s..."%(self.Pk[:16],self.current_key.pk[:16]))

    def _gen_kp(self, ts):
        # Paper: PKCA=KeyGen(IdCA,TS), SKCA=KeyGen(IdCA,TS)
        # Timestamp embedded -> stale-key detection on rotation
        import secrets as _sec
        salt=_sec.token_bytes(16)
        tsb=("%s_%.3f"%(self.id_ca,ts)).encode()
        pk=hashlib.sha256(tsb+salt).hexdigest()
        sk=hmac.new(self._MASTER_SECRET,tsb,hashlib.sha256).hexdigest()
        kp=CAKeyPair(pk=pk,sk=sk,ts=ts,salt=salt)
        self.key_history[pk]=kp; return kp

    def maybe_rotate_keys(self, sim_time):
        # Paper: "CA will timely update PK/SK pair... so old PKCA
        #         circulated in network may not be entertained."
        # Vehicles presenting stale PK_CA are flagged as impersonators.
        if (sim_time-self._last_rotation_sim_time)>=CA_KEY_ROTATION_INTERVAL:
            old=self.current_key.pk[:16]
            self.current_key=self._gen_kp(sim_time)
            self._last_rotation_sim_time=sim_time
            print("[CA] Key rotated @t=%.1fs %s...->%s..."%(
                sim_time,old,self.current_key.pk[:16])); return True
        return False

    def get_current_pk(self): return self.current_key.pk
    def get_proving_key(self): return self.Pk

    def register_vehicle(self, real_id, sim_time):
        # Algorithm 2: FIdv=Hash(Salt(Idv)), SKv=KeyGen(FIdv,SKCA)
        #   PKv=KeyGen(SKv,SKCA), CertCA(SKv,PKv)
        # PRIVACY: real_id one-way hashed with random salt -> fake_id
        # real_id stored NOWHERE except CA private memory
        import secrets as _sec
        salt_v=_sec.token_bytes(16)
        fake_id=hashlib.sha256(salt_v+real_id.encode()).hexdigest()[:32]
        sk_v=hmac.new(self.current_key.sk.encode(),
            (fake_id+"_priv").encode(),hashlib.sha256).hexdigest()
        pk_v=hmac.new(self.current_key.sk.encode(),
            (sk_v+fake_id).encode(),hashlib.sha256).hexdigest()
        cert=hmac.new(self.current_key.sk.encode(),
            (pk_v+fake_id).encode(),hashlib.sha256).hexdigest()
        # Store ONLY Hash(w): zero-knowledge property
        # Verifier checks Hash(Pk||x||Hash(w)) without seeing w=(SKv,PKv)
        w_hash=hashlib.sha256((sk_v+pk_v).encode()).hexdigest()
        self._witness_hashes[fake_id]=w_hash
        reg=VehicleRegistration(real_id=real_id,fake_id=fake_id,
            pk_v=pk_v,sk_v=sk_v,cert=cert,salt_v=salt_v,
            registered_at=sim_time,pk_ca_used=self.current_key.pk)
        self._registry[fake_id]=reg
        print("[CA] Registered %s -> FIdv=%s..."%(real_id,fake_id[:12]))
        return reg

    def verify_proof(self, fake_id, proof):
        # Algorithm 4: CA verification. Three security layers:
        # Layer1: stale key (Section IV) -> STALE_KEY rejection
        # Layer2: soundness (VI.A Eq21-22) -> x mismatch rejection
        # Layer3: ZK verify (VI.C Eq26-27) -> proof!=Hash(Pk||x||Hash(w))
        # Returns VerificationResult(accepted=True/False).
        # PL receives ONLY the accepted bit, never reason string.
        t0=time.perf_counter()
        if proof.pk_ca!=self.current_key.pk:
            if proof.pk_ca in self.key_history:
                r="STALE_KEY: t=%.1fs(current=%.1fs)"%(
                    self.key_history[proof.pk_ca].ts,self.current_key.ts)
            else: r="INVALID_KEY: unknown PK_CA"
            t1=time.perf_counter()
            return VerificationResult(False,r,0.0,(t1-t0)*1000)
        ex=hashlib.sha256((proof.sm+self.current_key.pk).encode()).hexdigest()
        if proof.x!=ex:
            t1=time.perf_counter()
            return VerificationResult(False,"SOUNDNESS_FAIL:x_mismatch",0.0,(t1-t0)*1000)
        if fake_id not in self._witness_hashes:
            t1=time.perf_counter()
            return VerificationResult(False,"NOT_REGISTERED:%s"%fake_id[:12],0.0,(t1-t0)*1000)
        ep=hashlib.sha256((self.Pk+proof.x+self._witness_hashes[fake_id]).encode()).hexdigest()
        t1=time.perf_counter(); vm=(t1-t0)*1000
        self.proof_verify_times.append(vm)
        if proof.proof==ep:
            self._auth_status[fake_id]=True
            return VerificationResult(True,"PROOF_VALID",0.0,vm)
        self._auth_status[fake_id]=False
        return VerificationResult(False,"COMPLETENESS_FAIL",0.0,vm)

    def is_authenticated(self,fid): return self._auth_status.get(fid,False)
    def get_registry_entry(self,fid): return self._registry.get(fid)

class VehicleIdentityManager:
    # Algorithms 2+3 per-vehicle handler.
    # Privacy: real_id used once at registration then discarded.
    # Efficiency: proof cached and reused within same PK_CA rotation
    # (avoids aggregate overhead of benchmark [2]).
    def __init__(self, real_id, ca):
        self.real_id=real_id; self.ca=ca
        self.registration=None; self.fake_id=None; self.pk_v=None
        self._sk_v_temp=None; self.latest_proof=None
        self.proof_gen_time_ms=0.0; self.is_authenticated=False

    def _register(self, sim_time):
        try:
            reg=self.ca.register_vehicle(self.real_id,sim_time)
            self.registration=reg; self.fake_id=reg.fake_id
            self.pk_v=reg.pk_v; self._sk_v_temp=reg.sk_v; return True
        except Exception as ex:
            print("[VIM] reg failed %s: %s"%(self.real_id,ex)); return False

    def generate_proof(self, sim_time):
        # Algorithm 3: sm=Hash(Salt(Sig_SKv,T)) Eq17
        #   x=Hash(sm||PKCA) Eq18, proof=Hash(Pk||x||Hash(w)) Eq20
        # ZK: w=(SK_v,PK_v) never appears in proof plaintext
        # Timing (Fig3): no Blockchain access needed here
        if self.registration is None: return None
        import secrets as _sec
        t0=time.perf_counter()
        sig=hmac.new(self._sk_v_temp.encode(),
            self.real_id.encode(),hashlib.sha256).hexdigest()
        sm=hashlib.sha256(
            _sec.token_bytes(8)+sig.encode()+str(sim_time).encode()).hexdigest()
        pk_ca=self.ca.get_current_pk()
        x=hashlib.sha256((sm+pk_ca).encode()).hexdigest()
        wh=hashlib.sha256((self._sk_v_temp+self.pk_v).encode()).hexdigest()
        proof_str=hashlib.sha256((self.ca.get_proving_key()+x+wh).encode()).hexdigest()
        t1=time.perf_counter()
        self.proof_gen_time_ms=(t1-t0)*1000
        self.ca.proof_gen_times.append(self.proof_gen_time_ms)
        self.latest_proof=ZKProof(sm=sm,x=x,proof=proof_str,timestamp=sim_time,pk_ca=pk_ca)
        return self.latest_proof

    def authenticate_with_ca(self, sim_time):
        # Figure 2 flow: register -> gen proof -> CA verify -> result
        # Proof reuse: same PK_CA + fresh timestamp -> skip regen
        if self.registration is None:
            if not self._register(sim_time):
                return VerificationResult(False,"REGISTRATION_FAILED")
        reuse=(self.latest_proof is not None
               and (sim_time-self.latest_proof.timestamp)<CA_PROOF_TIMESTAMP_WINDOW
               and self.latest_proof.pk_ca==self.ca.get_current_pk())
        proof=self.latest_proof if reuse else self.generate_proof(sim_time)
        if proof is None: return VerificationResult(False,"PROOF_GEN_FAILED")
        result=self.ca.verify_proof(self.fake_id,proof)
        self.is_authenticated=result.accepted
        result.proof_gen_ms=self.proof_gen_time_ms
        print("[CA] Auth %s: %s FIdv=%s gen=%.2fms verify=%.2fms | %s"%(
            "ACCEPTED" if result.accepted else "REJECTED",
            self.real_id,self.fake_id[:12] if self.fake_id else "?",
            self.proof_gen_time_ms,result.verify_ms,result.reason))
        return result

class SecurityPropertiesValidator:
    # Section VI: tracks soundness, completeness, zero-knowledge at runtime
    # Section V.B: impersonation detection + DDoS rate limiting
    def __init__(self):
        self.soundness_records=[]
        self.completeness_violations=[]
        self.completeness_acceptances=[]
        self.zk_violations=[]
        self.impersonation_attempts=[]
        self.ddos_events=[]
        self._msg_rate={}

    def check_soundness(self, vid, result, is_legitimate, sim_time):
        # VI.A Eq21-22: forged proof rejected=soundness holds
        # VI.B Eq23-25: honest vehicle accepted=completeness holds
        entry={"sim_time":sim_time,"vehicle_id":vid,
               "accepted":result.accepted,"legitimate":is_legitimate,
               "reason":result.reason}
        if not is_legitimate and result.accepted:
            entry["note"]="SOUNDNESS_VIOLATION"
            print("[SECURITY] SOUNDNESS VIOLATION forged accepted %s @t=%.1fs"%(vid,sim_time))
        self.soundness_records.append(entry)
        if is_legitimate:
            if result.accepted: self.completeness_acceptances.append(entry)
            else:
                entry["note"]="COMPLETENESS_VIOLATION"
                self.completeness_violations.append(entry)
                print("[SECURITY] COMPLETENESS VIOLATION honest %s rejected @t=%.1fs"%(vid,sim_time))

    def check_zero_knowledge(self, vid, proof, reg, sim_time):
        # VI.C Eq26-27: proof must NOT contain sk_v or pk_v
        vio=[]
        if reg.sk_v in proof.proof: vio.append("sk_v_in_proof")
        if reg.pk_v in proof.proof: vio.append("pk_v_in_proof")
        if reg.real_id in reg.fake_id: vio.append("real_id_in_fake_id")
        if vio: self.zk_violations.append({"sim_time":sim_time,"vehicle_id":vid,"violations":vio})

    def check_impersonation(self, vid, proof, ca, sim_time):
        # V.B: stale PK_CA in proof = credential leakage from malicious peer
        suspected=False; reasons=[]
        if proof.pk_ca!=ca.get_current_pk():
            suspected=True
            if proof.pk_ca in ca.key_history:
                reasons.append("stale_pk(t=%.1fs)"%ca.key_history[proof.pk_ca].ts)
            else: reasons.append("unknown_pk_ca")
        ex=hashlib.sha256((proof.sm+ca.get_current_pk()).encode()).hexdigest()
        if proof.x!=ex: suspected=True; reasons.append("x_tampered")
        if suspected:
            self.impersonation_attempts.append({"sim_time":sim_time,"vehicle_id":vid,"reasons":reasons})
            print("[SECURITY] IMPERSONATION suspected: %s | %s"%(vid,reasons))
        return suspected

    def record_message(self, vid, sim_time, is_authenticated):
        # V.B DDoS: "only authenticated RSUs/CAVs to use channel"
        # Authenticated vehicles bypass rate limit.
        if is_authenticated: return True
        w=self._msg_rate.setdefault(vid,[])
        w[:]=[t for t in w if sim_time-t<1.0]
        w.append(sim_time)
        if len(w)>DDOS_MSG_RATE_LIMIT:
            self.ddos_events.append({"sim_time":sim_time,"vehicle_id":vid,"count":len(w)})
            print("[DDoS] %s blocked %d msgs/s @t=%.1fs"%(vid,len(w),sim_time))
            return False
        return True

    def print_summary(self):
        print("\n"+"="*70)
        print("SECURITY PROPERTIES SUMMARY  Khan et al. IEEE TITS 2025")
        print("="*70)
        atk=[r for r in self.soundness_records if not r["legitimate"]]
        byp=[r for r in atk if r["accepted"]]
        print("\nVI.A PERFECTLY SOUND:")
        print("  Attack attempts  : %d"%len(atk))
        print("  Correctly blocked: %d"%(len(atk)-len(byp)))
        print("  VIOLATIONS (=0)  : %d"%len(byp))
        print("\nVI.B PERFECTLY COMPLETE:")
        print("  Legitimate accepted  : %d"%len(self.completeness_acceptances))
        print("  FALSE REJECTIONS (=0): %d"%len(self.completeness_violations))
        print("\nVI.C PERFECTLY ZERO-KNOWLEDGE:")
        print("  ZK violations (=0): %d"%len(self.zk_violations))
        print("\nV.B IMPERSONATION: %d attempts"%len(self.impersonation_attempts))
        print("V.B DDoS: %d blocking events"%len(self.ddos_events))
        print("="*70+"\n")

class PlatoonFormationCalculator:
    # Section V.A + Eq 13-16. T=proof gen time appears in all equations.
    # Individual proof approach (this system) -> lower T -> faster formation.
    def __init__(self): self.records=[]

    def _N(self, T, D, v1, vi, a1, ai, t=1.0):
        # Common numerator Eq12: T+D-(v1-vi)t/T+0.5*(a1+ai)*t^2/T
        if T<0.001: T=0.001
        return T+D-(v1-vi)*t/T+0.5*(a1+ai)*(t**2)/T

    def situation_1(self, vid, vi, v1, ai, a1, D, T):
        # Eq13: vehicle speeds up. Pi(t+T)=N/(vimin+vi)
        n=self._N(T,D,v1,vi,a1,ai); d=max(PLATOON_VMIN+vi,0.01)
        r=PlatoonFormationTiming(vid,1,vi,v1,ai,a1,D,T,n/d,n)
        self.records.append(r); return r

    def situation_2(self, vid, vi, v1, ai, a1, D, T):
        # Eq14: vehicle slows down. Pi(t+T)=N/(vimax-vi)
        n=self._N(T,D,v1,vi,a1,ai); d=max(PLATOON_VMAX-vi,0.01)
        r=PlatoonFormationTiming(vid,2,vi,v1,ai,a1,D,T,n/d,n)
        self.records.append(r); return r

    def situation_3(self, vid, vi, v1, ai, a1, D, T):
        # Eq15: standing vehicle. Pi(t+T)=N/[(vimin+vi)-(vimax-vi)]
        n=self._N(T,D,v1,vi,a1,ai)
        d=abs((PLATOON_VMIN+vi)-(PLATOON_VMAX-vi)) or 0.01
        r=PlatoonFormationTiming(vid,3,vi,v1,ai,a1,D,T,n/d,n)
        self.records.append(r); return r

    def situation_4(self, vid, vi, v1, ai, a1, D, T, vAmax=None):
        # Eq16: cooperative. Pi(t+T)=N/(vAmax-vimax)+v1
        if vAmax is None: vAmax=PLATOON_VMAX
        n=self._N(T,D,v1,vi,a1,ai)
        d=vAmax-PLATOON_VMAX; d=d if abs(d)>0.01 else 0.01
        r=PlatoonFormationTiming(vid,4,vi,v1,ai,a1,D,T,abs(n/d+v1),n)
        self.records.append(r); return r

    def compute(self, vid, sim_time):
        # Auto-detect situation from SUMO kinematics. T overridden after call.
        try: vi=float(traci.vehicle.getSpeed(vid))
        except: vi=LEADER_SPEED_MPS*0.9
        try: ai=float(traci.vehicle.getAcceleration(vid))
        except: ai=0.0
        lv=vid_for(0,0)
        try: v1=float(traci.vehicle.getSpeed(lv))
        except: v1=LEADER_SPEED_MPS
        try: a1=float(traci.vehicle.getAcceleration(lv))
        except: a1=0.0
        try:
            pi=traci.vehicle.getPosition(vid); pl=traci.vehicle.getPosition(lv)
            D=math.hypot(pi[0]-pl[0],pi[1]-pl[1])
        except: D=PLATOON_DESIRED_GAP
        T=0.05
        if vi<0.5: return self.situation_3(vid,vi,v1,ai,a1,D,T)
        elif vi<v1-0.5: return self.situation_1(vid,vi,v1,ai,a1,D,T)
        elif vi>v1+0.5: return self.situation_2(vid,vi,v1,ai,a1,D,T)
        else: return self.situation_4(vid,vi,v1,ai,a1,D,T)

    def print_summary(self):
        if not self.records: return
        print("\n"+"="*70)
        print("PLATOON FORMATION TIMING  Paper Section V.A Eq 13-16")
        print("="*70)
        for r in self.records[-10:]:
            print("  %-12s Sit=%d vi=%5.1f v1=%5.1f D=%6.1fm T=%5.1fms ft=%.3fs"%(
                r.vehicle_id,r.situation,r.v_i,r.v_1,
                r.distance_D,r.auth_time_T*1000,r.formation_time))
        print("="*70)

class SecurityEventLogger:
    # CSV logger for security events. Columns match paper Figs 3,4,5,6,8,10.
    def __init__(self):
        import os as _os; _os.makedirs(CATS_LOG_DIR,exist_ok=True)
        self.filepath=SECURITY_LOG_FILE; self._buf=[]
        with open(self.filepath,"w",newline="") as f:
            import csv as _csv
            _csv.writer(f).writerow(["sim_time","event_type","vehicle_id",
                "fake_id","proof_gen_ms","verify_ms","result",
                "situation","formation_time_s","detail"])
        print("[SecLog] %s"%self.filepath)

    def log_auth(self, sim_time, vid, fake_id, result, gen_ms):
        self._buf.append({"sim_time":round(sim_time,3),"event_type":"AUTH",
            "vehicle_id":vid,"fake_id":(fake_id[:16]+"..." if fake_id else ""),
            "proof_gen_ms":round(gen_ms,3),"verify_ms":round(result.verify_ms,3),
            "result":"ACCEPTED" if result.accepted else "REJECTED",
            "situation":"","formation_time_s":"","detail":result.reason[:80]})

    def log_formation(self, sim_time, timing):
        self._buf.append({"sim_time":round(sim_time,3),"event_type":"FORMATION",
            "vehicle_id":timing.vehicle_id,"fake_id":"",
            "proof_gen_ms":round(timing.auth_time_T*1000,3),"verify_ms":"",
            "result":"OK","situation":timing.situation,
            "formation_time_s":round(timing.formation_time,4),
            "detail":"D=%.1fm vi=%.1f v1=%.1f"%(timing.distance_D,timing.v_i,timing.v_1)})

    def log_security(self, sim_time, etype, vid, detail):
        self._buf.append({"sim_time":round(sim_time,3),"event_type":etype,
            "vehicle_id":vid,"fake_id":"","proof_gen_ms":"","verify_ms":"",
            "result":"EVENT","situation":"","formation_time_s":"","detail":detail[:120]})

    def flush(self):
        if not self._buf: return
        import csv as _csv
        with open(self.filepath,"a",newline="") as f:
            _csv.DictWriter(f,fieldnames=["sim_time","event_type","vehicle_id",
                "fake_id","proof_gen_ms","verify_ms","result",
                "situation","formation_time_s","detail"]).writerows(self._buf)
        self._buf.clear()

class BlockchainManager:
    """
    Manages two Ethereum smart contracts:
      • VehicleTrust  — per-vehicle trust score (80 set at login)
      • CATS          — per-commitment reputation, votes, flags
    All public methods are safe to call even if blockchain is unavailable;
    they log a warning and return gracefully.
    """

    def __init__(self):
        self.enabled          = False
        self.w3               = None
        self.deployer         = None
        self.cats_contract    = None
        self.trust_contract   = None

    # ----------------------------------------------------------
    def setup(self):
        """
        Connect to Ganache/Hardhat, compile both contracts with solcx,
        deploy them (or load from env-var addresses).
        Sets self.enabled = True on success.
        """
        try:
            from web3 import Web3
            self.w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_PROVIDER))
            if not self.w3.is_connected():
                print("[Blockchain] Provider not reachable — blockchain disabled")
                return
            self.deployer = self.w3.eth.accounts[0]
            print(f"[Blockchain] Connected  chainId={self.w3.eth.chain_id} "
                  f"deployer={self.deployer}")

            cats_abi, cats_bin   = self._compile(_CATS_SOURCE,         "CATS")
            vt_abi,   vt_bin     = self._compile(_VEHICLE_TRUST_SOURCE,"VehicleTrust")

            if ENV_CATS_ADDRESS:
                self.cats_contract  = self.w3.eth.contract(
                    address=ENV_CATS_ADDRESS, abi=cats_abi)
                print(f"[Blockchain] CATS loaded from {ENV_CATS_ADDRESS}")
            else:
                addr = self._deploy(cats_abi, cats_bin, "CATS")
                self.cats_contract = self.w3.eth.contract(address=addr, abi=cats_abi)

            if ENV_VEHICLE_TRUST_ADDRESS:
                self.trust_contract = self.w3.eth.contract(
                    address=ENV_VEHICLE_TRUST_ADDRESS, abi=vt_abi)
                print(f"[Blockchain] VehicleTrust loaded from "
                      f"{ENV_VEHICLE_TRUST_ADDRESS}")
            else:
                addr = self._deploy(vt_abi, vt_bin, "VehicleTrust")
                self.trust_contract = self.w3.eth.contract(address=addr, abi=vt_abi)

            self.enabled = True
            print("[Blockchain] Both contracts ready — blockchain ENABLED")

        except Exception as ex:
            print(f"[Blockchain] Setup failed ({ex}) — blockchain disabled")

    # ----------------------------------------------------------
    def _compile(self, source: str, contract_name: str):
        from solcx import compile_source, install_solc, set_solc_version
        try:
            set_solc_version("0.8.17")
        except Exception:
            install_solc("0.8.17")
            set_solc_version("0.8.17")
        compiled = compile_source(source)
        _, iface  = compiled.popitem()
        return iface["abi"], iface["bin"]

    def _deploy(self, abi, bytecode, label: str) -> str:
        Contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        tx = Contract.constructor().transact(
            {"from": self.deployer, "gas": BLOCKCHAIN_GAS_LIMIT}
        )
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        print(f"[Blockchain] {label} deployed → {receipt.contractAddress}")
        return receipt.contractAddress

    # ----------------------------------------------------------
    # ---- helpers ----
    def _commitment_to_bytes32(self, commitment_str: str) -> bytes:
        """Convert a large-integer string commitment to bytes32."""
        try:
            return int(commitment_str).to_bytes(32, "big")
        except Exception:
            return (0).to_bytes(32, "big")

    def _trust_state_int(self, trust_state_str: str) -> int:
        """CATS.sol: 0=Trusted, 1=Untrusted, 2=Banned"""
        mapping = {
            "Trusted":   0,
            "Untrusted": 1,
            "Banned":    2,
        }
        return mapping.get(trust_state_str, 0)

    # ----------------------------------------------------------
    # ---- public API ----

    def set_initial_trust_score(self, vehicle_id: str,
                                 commitment: str,
                                 score: int = 80) -> bool:
        """
        Called once per vehicle at login.
        1. Writes vehicleID → score in VehicleTrust.sol
        2. Writes commitment → (score, Trusted) initial reputation in CATS.sol
        3. Adds commitment to CATS commitments list with capability=score, trust=score
        Returns True on success.
        """
        if not self.enabled:
            return False
        try:
            # VehicleTrust: set score by string ID
            tx = self.trust_contract.functions.setTrustScore(
                vehicle_id, score
            ).transact({"from": self.deployer, "gas": BLOCKCHAIN_GAS_LIMIT})
            self.w3.eth.wait_for_transaction_receipt(tx)
            print(f"[Blockchain] VehicleTrust.setTrustScore({vehicle_id}, {score})")

            # CATS: register commitment + initial reputation
            b32 = self._commitment_to_bytes32(commitment)
            tx = self.cats_contract.functions.addCommitment(
                b32, score, score
            ).transact({"from": self.deployer, "gas": BLOCKCHAIN_GAS_LIMIT})
            self.w3.eth.wait_for_transaction_receipt(tx)

            tx = self.cats_contract.functions.updateReputation(
                b32, score, 0   # 0 = Trusted
            ).transact({"from": self.deployer, "gas": BLOCKCHAIN_GAS_LIMIT})
            self.w3.eth.wait_for_transaction_receipt(tx)
            print(f"[Blockchain] CATS.updateReputation({vehicle_id}, {score}, Trusted)")
            return True

        except Exception as ex:
            print(f"[Blockchain] set_initial_trust_score failed: {ex}")
            return False

    def get_initial_trust_score(self, vehicle_id: str) -> Optional[float]:
        """
        Read the trust score stored in VehicleTrust.sol for *vehicle_id*.
        Returns the score as a float, or None if blockchain is disabled /
        score is 0 (not yet registered).
        """
        if not self.enabled:
            return None
        try:
            score = self.trust_contract.functions.getTrustScore(
                vehicle_id
            ).call()
            if score > 0:
                print(f"[Blockchain] VehicleTrust.getTrustScore({vehicle_id}) = {score}")
                return float(score)
        except Exception as ex:
            print(f"[Blockchain] get_initial_trust_score failed: {ex}")
        return None

    def update_reputation_on_chain(self, commitment: str,
                                    score: float,
                                    trust_state_str: str) -> bool:
        """
        Write updated reputation to CATS.sol after each 1-second window.
        """
        if not self.enabled:
            return False
        try:
            b32       = self._commitment_to_bytes32(commitment)
            state_int = self._trust_state_int(trust_state_str)
            tx = self.cats_contract.functions.updateReputation(
                b32, int(score), state_int
            ).transact({"from": self.deployer, "gas": BLOCKCHAIN_GAS_LIMIT})
            self.w3.eth.wait_for_transaction_receipt(tx)
            return True
        except Exception as ex:
            print(f"[Blockchain] update_reputation_on_chain failed: {ex}")
            return False

    def add_flag_on_chain(self, commitment: str,
                           flag_type: str,
                           window_id: int) -> bool:
        """
        Record a trust-state flag (e.g. 'BANNED', 'UNTRUSTED') in CATS.sol.
        """
        if not self.enabled:
            return False
        try:
            b32 = self._commitment_to_bytes32(commitment)
            tx  = self.cats_contract.functions.addFlag(
                b32, flag_type, window_id
            ).transact({"from": self.deployer, "gas": BLOCKCHAIN_GAS_LIMIT})
            self.w3.eth.wait_for_transaction_receipt(tx)
            print(f"[Blockchain] CATS.addFlag({flag_type}, window={window_id})")
            return True
        except Exception as ex:
            print(f"[Blockchain] add_flag_on_chain failed: {ex}")
            return False

    def get_on_chain_reputation(self, commitment: str) -> Optional[dict]:
        """
        Read reputation stored in CATS.sol.
        Returns dict with keys: score, trust_state, last_updated — or None.
        """
        if not self.enabled:
            return None
        try:
            b32           = self._commitment_to_bytes32(commitment)
            score, state, ts = self.cats_contract.functions.getReputation(
                b32
            ).call()
            state_map = {0: "Trusted", 1: "Untrusted", 2: "Banned"}
            return {
                "score":        float(score),
                "trust_state":  state_map.get(state, "Trusted"),
                "last_updated": ts,
            }
        except Exception:
            return None


# ============================================================
#  DB VOTE / REPUTATION LOGGER  (PostgreSQL via asyncpg)
# ============================================================

# ---- Schema DDL -------------------------------------------
_DDL_VEHICLE_VOTES = """
CREATE TABLE IF NOT EXISTS vehicle_votes (
    id               SERIAL PRIMARY KEY,
    sim_time         DOUBLE PRECISION NOT NULL,
    target_vehicle_id VARCHAR(64),
    target_commitment VARCHAR(256),
    voter_vehicle_id  VARCHAR(64),
    vote_type         VARCHAR(32)  NOT NULL,
    message_type      VARCHAR(16),
    reason            VARCHAR(256),
    created_at        TIMESTAMP DEFAULT NOW()
);
"""

_DDL_REPUTATION_HISTORY = """
CREATE TABLE IF NOT EXISTS reputation_history (
    id               SERIAL PRIMARY KEY,
    sim_time         DOUBLE PRECISION NOT NULL,
    window_id        INTEGER,
    vehicle_id        VARCHAR(64),
    commitment        VARCHAR(256),
    old_reputation    DOUBLE PRECISION,
    new_reputation    DOUBLE PRECISION,
    reputation_change DOUBLE PRECISION,
    trust_state       VARCHAR(16),
    reason            TEXT,
    upvotes           INTEGER,
    downvotes         INTEGER,
    severe_downvotes  INTEGER,
    created_at        TIMESTAMP DEFAULT NOW()
);
"""

class DBVoteLogger:
    """
    Queues vote records and reputation history updates and flushes them
    to PostgreSQL at the end of each 1-second CATS reputation window.
    Mirrors the pattern of SimulationLogger so both CSV and DB stay in sync.
    """

    def __init__(self, db_config: dict):
        self.db_config       = db_config
        self.enabled         = False
        self._vote_queue:    List[dict] = []
        self._rep_queue:     List[dict] = []
        self._window_counter = 0

    # ----------------------------------------------------------
    def setup(self):
        """Create tables and set self.enabled = True if DB is reachable."""
        try:
            import asyncpg, asyncio
            async def _init():
                conn = await asyncpg.connect(**self.db_config)
                await conn.execute(_DDL_VEHICLE_VOTES)
                await conn.execute(_DDL_REPUTATION_HISTORY)
                await conn.close()
            asyncio.run(_init())
            self.enabled = True
            print("[DBVoteLogger] Tables ready — DB vote logging ENABLED")
        except Exception as ex:
            print(f"[DBVoteLogger] Setup failed ({ex}) — DB vote logging disabled")

    # ----------------------------------------------------------
    def queue_vote(self, sim_time: float,
                   target_vid: str, target_commitment: str,
                   voter_vid: str,  vote_type: str,
                   message_type: str = "", reason: str = ""):
        """Enqueue one vote record (non-blocking)."""
        self._vote_queue.append({
            "sim_time":          sim_time,
            "target_vehicle_id": target_vid,
            "target_commitment": target_commitment,
            "voter_vehicle_id":  voter_vid,
            "vote_type":         vote_type,
            "message_type":      message_type,
            "reason":            reason,
        })

    def queue_reputation(self, sim_time: float, vehicle_id: str,
                         commitment: str, update_info: dict):
        """Enqueue one reputation-window record (non-blocking)."""
        self._rep_queue.append({
            "sim_time":          sim_time,
            "window_id":         self._window_counter,
            "vehicle_id":        vehicle_id,
            "commitment":        commitment,
            "old_reputation":    update_info.get("old_reputation", 0),
            "new_reputation":    update_info.get("new_reputation", 0),
            "reputation_change": update_info.get("reputation_change", 0),
            "trust_state":       update_info.get("new_state", ""),
            "reason":            update_info.get("reason", ""),
            "upvotes":           update_info.get("upvotes", 0),
            "downvotes":         update_info.get("downvotes", 0),
            "severe_downvotes":  update_info.get("severe_downvotes", 0),
        })

    # ----------------------------------------------------------
    def flush(self):
        """Batch-insert all queued records into PostgreSQL."""
        if not self.enabled:
            self._vote_queue.clear()
            self._rep_queue.clear()
            return

        votes = list(self._vote_queue)
        reps  = list(self._rep_queue)
        self._vote_queue.clear()
        self._rep_queue.clear()
        self._window_counter += 1

        if not votes and not reps:
            return

        try:
            import asyncpg, asyncio

            async def _write():
                conn = await asyncpg.connect(**self.db_config)
                try:
                    if votes:
                        await conn.executemany(
                            """
                            INSERT INTO vehicle_votes
                              (sim_time, target_vehicle_id, target_commitment,
                               voter_vehicle_id, vote_type, message_type, reason)
                            VALUES ($1,$2,$3,$4,$5,$6,$7)
                            """,
                            [(r["sim_time"], r["target_vehicle_id"],
                              r["target_commitment"], r["voter_vehicle_id"],
                              r["vote_type"], r["message_type"], r["reason"])
                             for r in votes]
                        )
                    if reps:
                        await conn.executemany(
                            """
                            INSERT INTO reputation_history
                              (sim_time, window_id, vehicle_id, commitment,
                               old_reputation, new_reputation, reputation_change,
                               trust_state, reason,
                               upvotes, downvotes, severe_downvotes)
                            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                            """,
                            [(r["sim_time"], r["window_id"], r["vehicle_id"],
                              r["commitment"], r["old_reputation"],
                              r["new_reputation"], r["reputation_change"],
                              r["trust_state"], r["reason"],
                              r["upvotes"], r["downvotes"], r["severe_downvotes"])
                             for r in reps]
                        )
                finally:
                    await conn.close()

            asyncio.run(_write())

        except Exception as ex:
            print(f"[DBVoteLogger] flush failed: {ex}")


# ============================================================
#  CATS TRUST MODULE — MESSAGE TYPES
# ============================================================

class BeaconMessage:
    def __init__(self, sender_id, timestamp, seq_no, lane,
                 position, speed, acceleration):
        self.sender_id    = sender_id
        self.timestamp    = timestamp
        self.seq_no       = seq_no
        self.lane         = lane
        self.position     = position
        self.speed        = speed
        self.acceleration = acceleration
        self.msg_type     = 'BEACON'

    def to_dict(self):
        return {
            'msg_type': self.msg_type, 'sender_id': self.sender_id,
            'timestamp': self.timestamp, 'seq_no': self.seq_no,
            'lane': self.lane, 'position': self.position,
            'speed': self.speed, 'acceleration': self.acceleration,
        }


class ObstacleMessage:
    def __init__(self, sender_id, timestamp, seq_no,
                 obstacle_in_lane, obstacle_position, lane):
        self.sender_id         = sender_id
        self.timestamp         = timestamp
        self.seq_no            = seq_no
        self.obstacle_in_lane  = obstacle_in_lane
        self.obstacle_position = obstacle_position
        self.lane              = lane
        self.msg_type          = 'OBSTACLE'

    def to_dict(self):
        return {
            'msg_type': self.msg_type, 'sender_id': self.sender_id,
            'timestamp': self.timestamp, 'seq_no': self.seq_no,
            'obstacle_in_lane': self.obstacle_in_lane,
            'obstacle_position': self.obstacle_position, 'lane': self.lane,
        }


class MessageBroker:
    def __init__(self):
        self.inbox            = {}
        self.sequence_numbers = {}

    def initialize_vehicle(self, veh_id):
        self.inbox[veh_id]            = []
        self.sequence_numbers[veh_id] = 0

    def get_next_seq_no(self, sender_id):
        seq = self.sequence_numbers.get(sender_id, 0)
        self.sequence_numbers[sender_id] = seq + 1
        return seq

    def broadcast_message(self, message, sender_position, all_vehicle_states):
        for receiver_id, receiver_state in all_vehicle_states.items():
            if receiver_id == message.sender_id:
                continue
            if receiver_id not in self.inbox:
                self.inbox[receiver_id] = []
            distance = abs(receiver_state['position'] - sender_position)
            if distance <= CATS_COMM_RANGE:
                self.inbox[receiver_id].append(message)

    def get_inbox(self, veh_id):    return self.inbox.get(veh_id, [])
    def clear_inbox(self, veh_id):  self.inbox[veh_id] = []
    def clear_all_inboxes(self):
        for veh_id in self.inbox:
            self.inbox[veh_id] = []


def check_obstacle_exists(lane, position, timestamp):
    for obstacle in CATS_OBSTACLES:
        if (obstacle['lane'] == lane
                and obstacle['pos_start'] <= position <= obstacle['pos_end']
                and obstacle['t_start']   <= timestamp <= obstacle['t_end']):
            return True
    return False


# ============================================================
#  CATS TRUST MODULE — VOTE TYPES & VERIFIER
# ============================================================

class VoteType:
    UPVOTE          = 'UPVOTE'
    DOWNVOTE        = 'DOWNVOTE'
    SEVERE_DOWNVOTE = 'SEVERE_DOWNVOTE'
    NO_VOTE         = 'NO_VOTE'


class Verifier:
    def __init__(self):
        self.previous_states    = {}
        self.obstacle_reporters = {}

    def update_previous_state(self, veh_id, state):
        self.previous_states[veh_id] = {
            'position': state['position'], 'speed': state['speed'],
            'acceleration': state['acceleration'], 'timestamp': state['timestamp'],
        }

    def is_eligible_for_beacon_vote(self, receiver_state, sender_state):
        return abs(receiver_state['position'] - sender_state['position']) \
               <= CATS_BEACON_VERIFICATION_RANGE

    def is_eligible_for_obstacle_vote(self, receiver_state, obstacle_position):
        return abs(receiver_state['position'] - obstacle_position) \
               <= CATS_OBSTACLE_VERIFICATION_RANGE

    def verify_beacon(self, message):
        if not (CATS_MIN_SPEED <= message.speed <= CATS_MAX_SPEED):
            return VoteType.DOWNVOTE
        if not (CATS_MIN_ACCEL <= message.acceleration <= CATS_MAX_ACCEL):
            return VoteType.DOWNVOTE
        if message.sender_id in self.previous_states:
            prev = self.previous_states[message.sender_id]
            dt   = message.timestamp - prev['timestamp']
            if dt > 0:
                predicted = (prev['position']
                             + prev['speed'] * dt
                             + 0.5 * prev['acceleration'] * dt * dt)
                if abs(predicted - message.position) > CATS_POSITION_PREDICTION_THRESHOLD:
                    return VoteType.DOWNVOTE
        return VoteType.UPVOTE

    def verify_obstacle(self, message):
        exists = check_obstacle_exists(
            message.lane, message.obstacle_position, message.timestamp)
        if message.obstacle_in_lane and not exists:
            return VoteType.SEVERE_DOWNVOTE
        elif not message.obstacle_in_lane and exists:
            return VoteType.DOWNVOTE
        return VoteType.UPVOTE

    def register_obstacle_reporter(self, message):
        key = (message.lane,
               int(message.obstacle_position / 10) * 10,
               int(message.timestamp))
        if key not in self.obstacle_reporters:
            self.obstacle_reporters[key] = message.sender_id
            return True
        return False

    def process_message(self, receiver_id, message, receiver_state, sender_state):
        is_first_reporter = False
        if message.msg_type == 'BEACON':
            if not self.is_eligible_for_beacon_vote(receiver_state, sender_state):
                return VoteType.NO_VOTE, False
            vote = self.verify_beacon(message)
        elif message.msg_type == 'OBSTACLE':
            if not self.is_eligible_for_obstacle_vote(
                    receiver_state, message.obstacle_position):
                return VoteType.NO_VOTE, False
            vote = self.verify_obstacle(message)
            if vote == VoteType.UPVOTE and message.obstacle_in_lane:
                is_first_reporter = self.register_obstacle_reporter(message)
        else:
            return VoteType.NO_VOTE, False
        return vote, is_first_reporter


# ============================================================
#  CATS TRUST MODULE — REPUTATION MANAGER
#  (modified: initialize_vehicle accepts optional blockchain score)
# ============================================================

class TrustState:
    TRUSTED   = 'Trusted'
    UNTRUSTED = 'Untrusted'
    BANNED    = 'Banned'


class ReputationManager:
    def __init__(self):
        self.reputation             = {}
        self.trust_state            = {}
        self.votes_window           = {}
        self.first_obstacle_reporters = set()

    def initialize_vehicle(self, veh_id: str,
                            initial_score: Optional[float] = None):
        """
        Set up reputation for *veh_id*.
        *initial_score* — if provided (read from blockchain), use it;
                          otherwise fall back to CATS_INITIAL_REPUTATION (70).
        """
        score = initial_score if initial_score is not None \
            else CATS_INITIAL_REPUTATION
        self.reputation[veh_id]   = score
        self.trust_state[veh_id]  = self._get_trust_state(score)
        self.votes_window[veh_id] = {
            'upvotes': 0, 'downvotes': 0, 'severe_downvotes': 0
        }
        if initial_score is not None:
            print(f"[CATS] {veh_id} initial reputation = {score:.1f} "
                  f"(from blockchain)")
        else:
            print(f"[CATS] {veh_id} initial reputation = {score:.1f} "
                  f"(default fallback)")

    def override_score(self, veh_id: str, score: float):
        """
        Override an already-initialised vehicle's score.
        Used when blockchain registration completes after CATS init.
        """
        self.reputation[veh_id]  = score
        self.trust_state[veh_id] = self._get_trust_state(score)
        print(f"[CATS] {veh_id} reputation overridden → {score:.1f} "
              f"(blockchain)")

    def _get_trust_state(self, reputation_score):
        if reputation_score >= CATS_TRUSTED_THRESHOLD:
            return TrustState.TRUSTED
        elif reputation_score >= CATS_UNTRUSTED_THRESHOLD:
            return TrustState.UNTRUSTED
        return TrustState.BANNED

    def add_vote(self, target_veh_id, vote_type,
                 is_first_obstacle_reporter=False):
        if vote_type == VoteType.NO_VOTE:
            return
        if target_veh_id not in self.votes_window:
            self.votes_window[target_veh_id] = {
                'upvotes': 0, 'downvotes': 0, 'severe_downvotes': 0
            }
        w = self.votes_window[target_veh_id]
        if vote_type == VoteType.UPVOTE:
            w['upvotes'] += 1
        elif vote_type == VoteType.DOWNVOTE:
            w['downvotes'] += 1
        elif vote_type == VoteType.SEVERE_DOWNVOTE:
            w['severe_downvotes'] += 1
            w['downvotes']        += 1
        if is_first_obstacle_reporter:
            self.first_obstacle_reporters.add(target_veh_id)

    def update_reputation(self, veh_id):
        if veh_id not in self.votes_window:
            return None
        votes          = self.votes_window[veh_id]
        old_reputation = self.reputation.get(veh_id, CATS_INITIAL_REPUTATION)
        old_state      = self.trust_state.get(veh_id, TrustState.TRUSTED)

        total_votes       = votes['upvotes'] + votes['downvotes']
        reputation_change = 0
        reason            = []

        if total_votes > 0:
            upvote_ratio   = votes['upvotes']   / total_votes
            downvote_ratio = votes['downvotes'] / total_votes
            if upvote_ratio >= CATS_UPVOTE_THRESHOLD:
                reputation_change += CATS_UPVOTE_REWARD
                reason.append(f"+{CATS_UPVOTE_REWARD} (good behavior)")
            elif downvote_ratio >= CATS_DOWNVOTE_THRESHOLD:
                reputation_change -= CATS_DOWNVOTE_PENALTY
                reason.append(f"-{CATS_DOWNVOTE_PENALTY} (bad behavior)")

        if votes['severe_downvotes'] >= 1:
            reputation_change -= CATS_SEVERE_PENALTY
            reason.append(f"-{CATS_SEVERE_PENALTY} (false obstacle)")

        if veh_id in self.first_obstacle_reporters:
            reputation_change += CATS_CORRECT_OBSTACLE_REWARD
            reason.append(f"+{CATS_CORRECT_OBSTACLE_REWARD} (first obstacle)")

        new_reputation = max(CATS_MIN_REPUTATION,
                             min(CATS_MAX_REPUTATION,
                                 old_reputation + reputation_change))
        self.reputation[veh_id]  = new_reputation
        new_state                 = self._get_trust_state(new_reputation)
        self.trust_state[veh_id] = new_state

        return {
            'veh_id':            veh_id,
            'old_reputation':    old_reputation,
            'new_reputation':    new_reputation,
            'old_state':         old_state,
            'new_state':         new_state,
            'reputation_change': reputation_change,
            'reason':            ', '.join(reason) if reason else 'no change',
            'upvotes':           votes['upvotes'],
            'downvotes':         votes['downvotes'],
            'severe_downvotes':  votes['severe_downvotes'],
        }

    def clear_vote_window(self):
        for veh_id in self.votes_window:
            self.votes_window[veh_id] = {
                'upvotes': 0, 'downvotes': 0, 'severe_downvotes': 0
            }
        self.first_obstacle_reporters.clear()

    def get_reputation(self, veh_id):
        return self.reputation.get(veh_id, CATS_INITIAL_REPUTATION)

    def get_trust_state(self, veh_id):
        return self.trust_state.get(veh_id, TrustState.TRUSTED)

    def get_votes(self, veh_id):
        return self.votes_window.get(veh_id, {
            'upvotes': 0, 'downvotes': 0, 'severe_downvotes': 0
        })


# ============================================================
#  CATS TRUST MODULE — CSV SIMULATION LOGGER
# ============================================================

class SimulationLogger:
    def __init__(self):
        self.log_file_path = os.path.join(CATS_LOG_DIR, CATS_LOG_FILE)
        self.log_data      = []
        os.makedirs(CATS_LOG_DIR, exist_ok=True)

    def initialize_log_file(self):
        headers = [
            'timestamp', 'vehicle_id', 'reputation', 'trust_state',
            'upvotes', 'downvotes', 'severe_downvotes',
            'position', 'speed', 'acceleration', 'lane',
        ]
        with open(self.log_file_path, 'w', newline='') as f:
            csv.writer(f).writerow(headers)
        print(f"[CATS Logger] CSV initialised: {self.log_file_path}")

    def log_vehicle_data(self, timestamp, veh_id, reputation_data,
                         vehicle_state, votes):
        row = {
            'timestamp':        round(timestamp, 2),
            'vehicle_id':       veh_id,
            'reputation':       round(reputation_data['reputation'], 2),
            'trust_state':      reputation_data['trust_state'],
            'upvotes':          votes['upvotes'],
            'downvotes':        votes['downvotes'],
            'severe_downvotes': votes['severe_downvotes'],
            'position':         round(vehicle_state['position'], 2)     if vehicle_state else 0,
            'speed':            round(vehicle_state['speed'], 2)        if vehicle_state else 0,
            'acceleration':     round(vehicle_state['acceleration'], 2) if vehicle_state else 0,
            'lane':             vehicle_state['lane']                   if vehicle_state else '',
        }
        self.log_data.append(row)

    def write_to_file(self):
        if not self.log_data:
            return
        with open(self.log_file_path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(self.log_data[0].keys()))
            writer.writerows(self.log_data)
        self.log_data.clear()

    def log_event(self, timestamp, event_type, details):
        print(f"[{round(timestamp, 2)}s] {event_type}: {details}")

    def log_reputation_update(self, timestamp, update_info):
        if update_info['old_state'] != update_info['new_state']:
            self.log_event(
                timestamp, 'STATE_CHANGE',
                f"{update_info['veh_id']}: {update_info['old_state']} → "
                f"{update_info['new_state']} "
                f"(R: {update_info['old_reputation']:.1f} → "
                f"{update_info['new_reputation']:.1f})"
            )
        if update_info['reputation_change'] != 0:
            print(
                f"  [{update_info['veh_id']}] "
                f"R: {update_info['old_reputation']:.1f} → "
                f"{update_info['new_reputation']:.1f} | "
                f"Votes: ↑{update_info['upvotes']} "
                f"↓{update_info['downvotes']} "
                f"⚠{update_info['severe_downvotes']} | "
                f"{update_info['reason']}"
            )

    def print_summary(self, all_vehicles, reputation_manager):
        print("\n" + "=" * 70)
        print("CATS SIMULATION SUMMARY")
        print("=" * 70)
        for veh_id in sorted(all_vehicles):
            reputation  = reputation_manager.get_reputation(veh_id)
            trust_state = reputation_manager.get_trust_state(veh_id)
            flag        = " [MALICIOUS]" if veh_id == CATS_MALICIOUS_VEHICLE_ID else ""
            print(f"{veh_id}{flag:15s} | "
                  f"Reputation: {reputation:5.1f} | State: {trust_state}")
        print("=" * 70)
        print(f"Log file: {self.log_file_path}")
        print("=" * 70 + "\n")


# ============================================================
#  CATS TRUST MODULE — PLOTTER
# ============================================================

class SimulationPlotter:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.data          = None
        os.makedirs(CATS_PLOT_DIR, exist_ok=True)

    def load_data(self):
        try:
            import pandas as pd
            self.data = pd.read_csv(self.log_file_path)
            print(f"[CATS Plotter] Loaded {len(self.data)} rows")
            return True
        except FileNotFoundError:
            print(f"[CATS Plotter] Log file not found: {self.log_file_path}")
            return False
        except ImportError:
            print("[CATS Plotter] pandas not installed — skipping plots")
            return False

    def _save(self, plt, name):
        import matplotlib.pyplot as _plt
        path = os.path.join(CATS_PLOT_DIR, name)
        _plt.tight_layout()
        _plt.savefig(path, dpi=300)
        print(f"[CATS Plotter] Saved: {path}")
        _plt.close()

    def plot_reputation_over_time(self):
        if self.data is None:
            return
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            return
        plt.figure(figsize=(14, 8))
        for veh_id in sorted(self.data['vehicle_id'].unique()):
            vd = self.data[self.data['vehicle_id'] == veh_id]
            if veh_id == CATS_MALICIOUS_VEHICLE_ID:
                plt.plot(vd['timestamp'], vd['reputation'],
                         label=f'{veh_id} (Malicious)', linewidth=2.5,
                         color='red', linestyle='--', marker='o', markersize=3)
            else:
                plt.plot(vd['timestamp'], vd['reputation'],
                         label=veh_id, linewidth=1.5, alpha=0.7)
        plt.axhline(y=CATS_TRUSTED_THRESHOLD,   color='green',  linestyle=':', linewidth=2,
                    label=f'Trusted ({CATS_TRUSTED_THRESHOLD})',   alpha=0.5)
        plt.axhline(y=CATS_UNTRUSTED_THRESHOLD, color='orange', linestyle=':', linewidth=2,
                    label=f'Untrusted ({CATS_UNTRUSTED_THRESHOLD})', alpha=0.5)
        plt.axvspan(CATS_FALSE_OBSTACLE_START_TIME,   CATS_FALSE_OBSTACLE_END_TIME,
                    alpha=0.15, color='red',    label='False Obstacle Attack')
        plt.axvspan(CATS_INCORRECT_BEACON_START_TIME, CATS_INCORRECT_BEACON_END_TIME,
                    alpha=0.15, color='orange', label='Incorrect Beacon Attack')
        plt.xlabel('Time (s)'); plt.ylabel('Reputation Score')
        plt.title('Vehicle Reputation Over Time (CATS + ZKP Platoon)',
                  fontsize=14, fontweight='bold')
        plt.legend(loc='best', fontsize=9, ncol=2)
        plt.grid(True, alpha=0.3); plt.ylim(-5, 105)
        self._save(plt, 'reputation_over_time.png')

    def plot_trust_state_timeline(self):
        if self.data is None:
            return
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            return
        plt.figure(figsize=(14, 6))
        state_map   = {TrustState.TRUSTED: 2, TrustState.UNTRUSTED: 1, TrustState.BANNED: 0}
        vehicle_ids = sorted(self.data['vehicle_id'].unique())
        for idx, veh_id in enumerate(vehicle_ids):
            vd     = self.data[self.data['vehicle_id'] == veh_id]
            states = vd['trust_state'].map(state_map)
            if veh_id == CATS_MALICIOUS_VEHICLE_ID:
                plt.plot(vd['timestamp'], states + idx * 3,
                         label=f'{veh_id} (Malicious)', linewidth=2,
                         color='red', marker='s', markersize=2)
            else:
                plt.plot(vd['timestamp'], states + idx * 3,
                         label=veh_id, linewidth=1.5, alpha=0.7)
        plt.xlabel('Time (s)'); plt.ylabel('Trust State (offset per vehicle)')
        plt.title('Trust State Timeline', fontsize=14, fontweight='bold')
        plt.legend(loc='best', fontsize=9, ncol=2)
        plt.grid(True, alpha=0.3)
        self._save(plt, 'trust_state_timeline.png')

    def plot_vote_distribution(self):
        if self.data is None:
            return
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            return
        vote_summary = self.data.groupby('vehicle_id').agg(
            {'upvotes': 'sum', 'downvotes': 'sum', 'severe_downvotes': 'sum'}
        ).reset_index()
        vehicle_ids = sorted(vote_summary['vehicle_id'].unique())
        fig, ax     = plt.subplots(figsize=(12, 6))
        x           = range(len(vehicle_ids))
        width       = 0.25
        def _val(v, col):
            r = vote_summary[vote_summary['vehicle_id'] == v][col].values
            return r[0] if len(r) else 0
        ax.bar([i - width for i in x],
               [_val(v,'upvotes') for v in vehicle_ids],
               width, label='Upvotes', color='green', alpha=0.7)
        ax.bar(list(x),
               [_val(v,'downvotes') for v in vehicle_ids],
               width, label='Downvotes', color='orange', alpha=0.7)
        ax.bar([i + width for i in x],
               [_val(v,'severe_downvotes') for v in vehicle_ids],
               width, label='Severe Downvotes', color='red', alpha=0.7)
        ax.set_xlabel('Vehicle ID'); ax.set_ylabel('Vote Count')
        ax.set_title('Total Vote Distribution', fontsize=14, fontweight='bold')
        ax.set_xticks(list(x))
        ax.set_xticklabels(vehicle_ids, rotation=45, ha='right')
        ax.legend(); ax.grid(True, alpha=0.3, axis='y')
        self._save(plt, 'vote_distribution.png')

    def generate_all_plots(self):
        if not self.load_data():
            return
        print("\n[CATS Plotter] Generating plots…")
        self.plot_reputation_over_time()
        self.plot_trust_state_timeline()
        self.plot_vote_distribution()
        print("[CATS Plotter] All plots generated!\n")


# ============================================================
#  CATS TRUST MODULE — VEHICLE STATE MANAGER (trust-side)
# ============================================================

class TrustVehicleManager:
    def __init__(self):
        self.vehicle_states      = {}
        self.last_beacon_time    = {}
        self.last_obstacle_check = {}
        self.applied_actions     = {}

    def update_vehicle_state(self, veh_id, current_time):
        try:
            position     = traci.vehicle.getLanePosition(veh_id)
            speed        = traci.vehicle.getSpeed(veh_id)
            acceleration = traci.vehicle.getAcceleration(veh_id)
            lane         = traci.vehicle.getLaneID(veh_id)
            state = {
                'position': position, 'speed': speed,
                'acceleration': acceleration, 'lane': lane,
                'timestamp': current_time,
            }
            self.vehicle_states[veh_id] = state
            return state
        except Exception:
            return None

    def get_vehicle_state(self, veh_id):
        return self.vehicle_states.get(veh_id)

    def should_send_beacon(self, veh_id, current_time):
        last = self.last_beacon_time.get(veh_id)
        if last is None:
            self.last_beacon_time[veh_id] = current_time
            return True
        if (current_time - last) >= CATS_BEACON_INTERVAL:
            self.last_beacon_time[veh_id] = current_time
            return True
        return False

    def should_send_false_obstacle(self, veh_id, current_time):
        if veh_id != CATS_MALICIOUS_VEHICLE_ID:
            return False
        if not (CATS_FALSE_OBSTACLE_START_TIME
                <= current_time
                <= CATS_FALSE_OBSTACLE_END_TIME):
            return False
        last = self.last_obstacle_check.get(veh_id, 0)
        if (current_time - last) >= CATS_FALSE_OBSTACLE_INTERVAL:
            self.last_obstacle_check[veh_id] = current_time
            return True
        return False

    def get_malicious_behavior(self, veh_id, current_time, real_state):
        if veh_id != CATS_MALICIOUS_VEHICLE_ID:
            return None
        if (CATS_INCORRECT_BEACON_START_TIME
                <= current_time
                <= CATS_INCORRECT_BEACON_END_TIME):
            s = real_state.copy()
            s['position'] += CATS_INCORRECT_POSITION_OFFSET
            s['speed']    *= CATS_INCORRECT_SPEED_MULTIPLIER
            return s
        return None

    def apply_trust_based_actions(self, veh_id, trust_state):
        if self.applied_actions.get(veh_id) == trust_state:
            return
        try:
            if veh_id not in traci.vehicle.getIDList():
                return
            if trust_state == TrustState.TRUSTED:
                traci.vehicle.setTau(veh_id, CATS_TRUSTED_TAU)
                traci.vehicle.setSpeedMode(veh_id, 31)
                self.applied_actions[veh_id] = TrustState.TRUSTED
            elif trust_state == TrustState.UNTRUSTED:
                traci.vehicle.setTau(veh_id, CATS_UNTRUSTED_TAU)
                self.applied_actions[veh_id] = TrustState.UNTRUSTED
            elif trust_state == TrustState.BANNED:
                traci.vehicle.setTau(veh_id, 5.0)
                traci.vehicle.setSpeed(veh_id, CATS_BANNED_SPEED)
                self.applied_actions[veh_id] = TrustState.BANNED
        except Exception:
            pass


# ============================================================
#  SUMO ZKP — ORIGINAL IMPORTS & GLOBAL DEPENDENCIES
# ============================================================

from traci.exceptions import FatalTraCIError

try:
    import traci
except Exception:
    traci = None

grpc_client = None
platoon_ops = None
intra_ops   = None
server_mod  = None
sumo_ops    = None
try:
    import client as grpc_client
except Exception:
    grpc_client = None
try:
    import platoon_ops
    platoon_ops = platoon_ops
except Exception:
    platoon_ops = None
try:
    import intra_platoon_ops
    intra_ops = intra_platoon_ops
except Exception:
    intra_ops = None
try:
    import server as server_mod
except Exception:
    server_mod = None
try:
    import sumo_ops
except Exception:
    sumo_ops = None

import asyncpg
import asyncio
import requests

NODE_URL = "http://localhost:4000"

DB_CONFIG = {
    "user":     "postgres",
    "password": "5112",
    "database": "avplatoon",
    "host":     "localhost",
    "port":     5432,
}


async def get_conn():
    return await asyncpg.connect(**DB_CONFIG)


async def insert_commitment(commitment):
    conn = await get_conn()
    await conn.execute(
        "INSERT INTO authorized_vehicles (commitment) VALUES ($1)",
        commitment
    )
    await conn.close()


async def get_commitments():
    conn = await get_conn()
    rows = await conn.fetch(
        "SELECT commitment FROM authorized_vehicles ORDER BY id"
    )
    await conn.close()
    return [str(r["commitment"]) for r in rows]


def build_merkle(commitment, all_commitments):
    idx = all_commitments.index(str(commitment))
    if idx % 2 == 0:
        left       = all_commitments[idx]
        right      = all_commitments[idx+1] if idx+1 < len(all_commitments) else "0"
        path_index = 0
        sibling    = right
    else:
        left       = all_commitments[idx-1]
        right      = all_commitments[idx]
        path_index = 1
        sibling    = left
    resp = requests.post(f"{NODE_URL}/zkp/hash-pair",
                         json={"a": left, "b": right})
    root = str(resp.json()["hash"])
    print(resp.json())
    print({"pathElements": [str(sibling)],
           "pathIndices":  [path_index],
           "merkle_root":  root})
    return {"pathElements": [str(sibling)],
            "pathIndices":  [path_index],
            "merkle_root":  root}


def register_vehicle(vehicle_secret: str,
                     manufacturer_signature: str) -> Optional[str]:
    data = {"vehicle_secret": vehicle_secret,
            "manufacturer_signature": manufacturer_signature}
    try:
        resp = requests.post(f"{NODE_URL}/zkp/commitment", json=data, timeout=5)
        resp.raise_for_status()
        commitment = resp.json().get("commitment")
        if commitment is not None:
            try:
                asyncio.run(insert_commitment(commitment))
            except Exception:
                pass
            return str(commitment)
    except Exception:
        return None
    return None


def auth_vehicle(commitment: str, vehicle_secret: str,
                 manufacturer_signature: str,
                 capability_score: int, trust_token: str,
                 capability_threshold: int = 60,
                 trust_threshold: int = 50) -> str:
    try:
        all_commitments = asyncio.run(get_commitments())
    except Exception:
        all_commitments = []
    if str(commitment) not in all_commitments:
        return "REJECTED"
    merkle = build_merkle(commitment, all_commitments)
    zkp_input = {
        "vehicle_secret":         vehicle_secret,
        "manufacturer_signature": manufacturer_signature,
        "pathElements":           merkle["pathElements"],
        "pathIndices":            merkle["pathIndices"],
        "merkle_root":            merkle["merkle_root"],
        "capability_score":       capability_score,
        "trust_token":            trust_token,
        "capability_threshold":   capability_threshold,
        "trust_threshold":        trust_threshold,
    }
    try:
        resp = requests.post(f"{NODE_URL}/zkp/verify-vehicle",
                             json=zkp_input, timeout=5)
        resp.raise_for_status()
        return resp.json().get("status", "REJECTED")
    except Exception:
        return "REJECTED"


# ============================================================
#  SUMO ZKP — SIMULATION CONSTANTS
# ============================================================

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SUMO_GROUP  = os.path.join(BASE_DIR, "sumo_platoon")
TMP_SUMOCFG = os.path.join(SUMO_GROUP, "tmp_generated.sumocfg")

STEP_LENGTH = 0.1
SIM_SECONDS = 270
SIM_STEPS   = int(SIM_SECONDS / STEP_LENGTH)

FAST_SIM  = True
SIM_SLEEP = 0.01 if FAST_SIM else STEP_LENGTH

PLATOON_COUNT  = 2
PLATOON_SIZES  = [6, 3]
DEPART_BASE    = 1.0
DEPART_GAP     = 1.8
LEADER_SPEED_MPS           = 12.0
PLATOON2_SPEED_MULTIPLIER  = 1.35
PLATOON2_MIN_SPEED         = 5.0
PLATOON2_SLOW_K            = 0.15
LEAVE_AFTER_MERGE_SEC      = 6.0

JUNCTION_TRIGGER_DIST = 60.0
SPAWN_AHEAD_SEC       = 1.5
MERGE_APPROACH_DIST   = 200.0

PLATOON_DESIRED_GAP = 20.0
PLATOON_CTRL_K      =  0.6

MERGE_TARGET_DIST  = 35.0
MERGE_TOLERANCE    =  0.75
MERGE_SLOW_REGION  = 120.0

SIDE1_FORCE_SPAWN_STEP = 1340
SIDE1_ARRIVE_STEP      = 1640

SLOW_START_STEP    = 1620
MERGE_EXECUTE_STEP = 1800

LAST_VEHICLE_SWAP_STEP = int(SIM_STEPS * 0.85)

PLATOON_COLORS: List[Tuple[int, int, int, int]] = [
    (220,  20,  20, 255),
    ( 20, 140, 240, 255),
    ( 20, 220,  80, 255),
]

SELECTED_MAIN_EDGE  = "main_0"
SELECTED_SIDE1_EDGE = "side1"
SELECTED_SIDE2_EDGE = "side2"

msg_q = queue.Queue()
cmd_q = queue.Queue()

rsu_positions:  Dict[str, Tuple[float, float]] = {}
vid_confidence: Dict[str, float] = {}

# Maps vehicle ID → ZKP commitment string (populated during registration)
vid_to_commitment: Dict[str, str] = {}

CATS_SIMULATION_STEP = STEP_LENGTH


def safe_put(q, s):
    try:
        q.put(s)
    except Exception:
        pass


def _apply_common_platoon_color(vids, color):
    if not vids or color is None:
        return
    for v in vids:
        try:
            traci.vehicle.setColor(v, color)
        except Exception:
            try:
                traci.vehicle.setColor(v, list(color))
            except Exception:
                pass


def _collect_and_force_recolour_merged(target_pidx, pids_map,
                                        prefer_prefix=None):
    global vid_platoon_index, vid_to_pid, colored
    try:
        present = traci.vehicle.getIDList()
    except Exception:
        present = []
    candidates = set()
    for v in present:
        try:
            if vid_platoon_index.get(v) in (0, 1):
                candidates.add(v); continue
            if vid_to_pid.get(v) in (pids_map.get(0), pids_map.get(1)):
                candidates.add(v); continue
            if prefer_prefix and v.startswith(prefer_prefix):
                candidates.add(v)
        except Exception:
            continue
    if not candidates:
        return None
    vids = sorted(list(candidates))
    for v in vids:
        try:
            colored.discard(v)
        except Exception:
            try:
                colored.remove(v)
            except Exception:
                pass
    for v in vids:
        try:
            vid_platoon_index[v] = target_pidx
        except Exception:
            pass
        try:
            vid_to_pid[v] = pids_map.get(target_pidx)
        except Exception:
            pass
    try:
        colour = PLATOON_COLORS[target_pidx % len(PLATOON_COLORS)]
    except Exception:
        colour = PLATOON_COLORS[0]
    for v in vids:
        try:
            traci.vehicle.setColor(v, colour)
        except Exception:
            try:
                traci.vehicle.setColor(v, list(colour))
            except Exception:
                pass
        try:
            colored.add(v)
        except Exception:
            pass
    try:
        leader = bully_elect_leader(vids) or vids[0]
        try:
            traci.vehicle.setColor(leader, (255, 240, 0, 255))
        except Exception:
            pass
        try:
            colored.add(leader)
        except Exception:
            pass
        return leader
    except Exception:
        return vids[0]


def overlay_thread(q, cmd_q):
    try:
        import tkinter as tk
    except Exception:
        return
    root = tk.Tk()
    root.title("Platoon Controls / Log")
    root.geometry("520x360+900+60")
    root.attributes("-topmost", True)
    f = tk.Frame(root)
    f.pack(side="top", fill="x")
    tk.Button(f, text="Quit SIM", width=12,
              command=lambda c="quit_sim": cmd_q.put(c)).pack(
        side="left", padx=4, pady=4)
    txt = tk.Text(root, bg="#111", fg="#fff", wrap="word",
                  font=("Consolas", 10))
    txt.pack(fill="both", expand=True, padx=6, pady=(0, 6))

    def poll():
        stop = False
        while True:
            try:
                s = q.get_nowait()
            except queue.Empty:
                break
            if s == "__QUIT__":
                stop = True; break
            try:
                txt.config(state="normal")
                txt.insert("end", f"{s}\n")
                txt.see("end")
                txt.config(state="disabled")
            except Exception:
                pass
        if stop:
            root.destroy(); return
        root.after(200, poll)

    root.after(200, poll)
    root.mainloop()


def load_rsu_positions():
    global rsu_positions
    rsu_positions = {}
    cand = os.path.join(SUMO_GROUP, "rsu.add.xml")
    if os.path.exists(cand):
        try:
            tree = ET.parse(cand)
            root = tree.getroot()
            for poi in root.findall(".//poi"):
                pid = poi.get("id") or poi.get("name")
                x   = poi.get("x"); y = poi.get("y")
                if pid and x and y:
                    try:
                        rsu_positions[pid] = (float(x), float(y))
                    except Exception:
                        continue
            safe_put(msg_q, f"[RSU] loaded {len(rsu_positions)} POIs from rsu.add.xml")
            return
        except Exception:
            pass
    netp = find_file_in_sumogroup(["guindy.net.xml", "guindy.net"])
    if netp and os.path.exists(netp):
        try:
            tree = ET.parse(netp)
            root = tree.getroot()
            idx  = 0
            for node in root.findall(".//poi"):
                pid = node.get("id") or f"rsu_{idx}"
                x   = node.get("x"); y = node.get("y")
                if pid and x and y:
                    try:
                        rsu_positions[pid] = (float(x), float(y)); idx += 1
                    except Exception:
                        continue
            safe_put(msg_q, f"[RSU] loaded {len(rsu_positions)} POIs from net")
            return
        except Exception:
            pass
    safe_put(msg_q, "[RSU] no rsu.add.xml — using nearest-edge heuristic")


def get_nearest_rsu_for_position(x, y):
    best_id = None; best_d = float("inf")
    try:
        for pid, (rx, ry) in rsu_positions.items():
            d = math.hypot(rx - x, ry - y)
            if d < best_d:
                best_d = d; best_id = pid
    except Exception:
        return None
    return best_id


def get_nearest_rsu_for_vid(vid):
    try:
        pos = traci.vehicle.getPosition(vid)
        if pos:
            return get_nearest_rsu_for_position(pos[0], pos[1])
    except Exception:
        pass
    return None


def get_n_nearest_rsus_for_vid(vid, n=3):
    out = []
    try:
        pos = traci.vehicle.getPosition(vid)
        if not pos:
            return []
        x, y = pos[0], pos[1]
        for pid, (rx, ry) in rsu_positions.items():
            try:
                out.append((math.hypot(rx - x, ry - y), pid))
            except Exception:
                continue
        out.sort(key=lambda t: t[0])
        return [pid for _, pid in out[:n]]
    except Exception:
        return list(rsu_positions.keys())[:n]


def find_sumo_binary():
    for name in ("sumo-gui", "sumo-gui.exe", "sumo", "sumo.exe"):
        p = shutil.which(name)
        if p:
            return p
    home = os.environ.get("SUMO_HOME")
    if home:
        for exe in ("bin/sumo-gui", "bin/sumo-gui.exe",
                    "bin/sumo", "bin/sumo.exe"):
            p = os.path.join(home, exe)
            if os.path.exists(p):
                return p
    return None


def parse_net_graph(net_path):
    edges = {}; outs = {}
    try:
        tree = ET.parse(net_path)
        root = tree.getroot()
        for edge in root.findall(".//edge"):
            eid = edge.get("id")
            if not eid or eid.startswith(":"):
                continue
            fromNode = edge.get("from"); toNode = edge.get("to")
            if fromNode is None or toNode is None:
                continue
            edges[eid] = (fromNode, toNode)
            outs.setdefault(fromNode, []).append(eid)
    except Exception:
        return {}, {}
    return edges, outs


def build_connected_route_from_net(start_edge, edges, outs, max_hops=12):
    route = []
    if not start_edge or start_edge not in edges:
        return route
    visited = set()
    curr    = start_edge
    route.append(curr); visited.add(curr)
    for _ in range(max_hops - 1):
        try:
            _, toNode = edges[curr]
        except Exception:
            break
        candidates = [e for e in outs.get(toNode, [])
                      if e not in visited and not e.startswith(":")]
        if not candidates:
            break
        nxt = candidates[0]
        route.append(nxt); visited.add(nxt); curr = nxt
    return route


def parse_net_edge_ids(net_path, max_edges=20):
    out = []
    try:
        tree = ET.parse(net_path)
        root = tree.getroot()
        for edge in root.findall(".//edge"):
            eid = edge.get("id")
            if eid and not eid.startswith(":"):
                out.append(eid)
                if len(out) >= max_edges:
                    break
    except Exception:
        return []
    return out


def ensure_sumocfg():
    net    = find_file_in_sumogroup(["guindy.net.xml", "guindy.net",
                                     "guindy.net.xml.gz"])
    routes = find_file_in_sumogroup(["route.rou.xml", "routes.rou.xml",
                                     "route.rou"])
    if not net:
        raise FileNotFoundError("guindy.net.xml missing in sumo_platoon folder")
    if not routes:
        routes     = os.path.join(SUMO_GROUP, "route.rou.xml")
        edge_ids   = parse_net_edge_ids(net, max_edges=12)
        if not edge_ids:
            edge_ids = [SELECTED_MAIN_EDGE, SELECTED_SIDE1_EDGE,
                        SELECTED_SIDE2_EDGE]
        edges_graph, outs = parse_net_graph(net)
        main_start  = (SELECTED_MAIN_EDGE  if SELECTED_MAIN_EDGE  in edge_ids
                       else (edge_ids[0] if edge_ids else SELECTED_MAIN_EDGE))
        side1_start = (SELECTED_SIDE1_EDGE if SELECTED_SIDE1_EDGE in edge_ids
                       else (edge_ids[1] if len(edge_ids) > 1 else main_start))
        side2_start = (SELECTED_SIDE2_EDGE if SELECTED_SIDE2_EDGE in edge_ids
                       else (edge_ids[2] if len(edge_ids) > 2 else main_start))
        if edges_graph:
            r_main_list  = build_connected_route_from_net(
                               main_start,  edges_graph, outs, 6) or [main_start]
            r_side1_list = build_connected_route_from_net(
                               side1_start, edges_graph, outs, 4) or [side1_start]
            r_side2_list = build_connected_route_from_net(
                               side2_start, edges_graph, outs, 4) or [side2_start]
        else:
            r_main_list  = edge_ids[:4] if len(edge_ids) >= 4 else edge_ids
            r_side1_list = [side1_start]; r_side2_list = [side2_start]
        try:
            with open(routes, "w", encoding="utf8") as f:
                f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<routes>
  <vType id="car" accel="2.6" decel="4.5" sigma="0.5" length="4.5" maxSpeed="13.9"/>
  <route id="r_main"  edges="{' '.join(r_main_list)}"/>
  <route id="r_side1" edges="{' '.join(r_side1_list)}"/>
  <route id="r_side2" edges="{' '.join(r_side2_list)}"/>
</routes>
""")
            safe_put(msg_q, f"[SUMO] generated route file → {routes}")
        except Exception as e:
            raise RuntimeError(f"failed to create default route file: {e}")
    with open(TMP_SUMOCFG, "w", encoding="utf8") as f:
        f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <input>
    <net-file value="{os.path.basename(net)}"/>
    <route-files value="{os.path.basename(routes)}"/>
    <additional-files value="rsu.add.xml"/>
  </input>
  <time>
    <begin value="0"/>
    <end value="{SIM_SECONDS}"/>
    <step-length value="{STEP_LENGTH}"/>
  </time>
  <gui><start value="true"/></gui>
</configuration>
""")
    safe_put(msg_q, f"[SUMO] wrote {TMP_SUMOCFG}")
    return TMP_SUMOCFG


def find_file_in_sumogroup(candidates):
    for n in candidates:
        p = os.path.join(SUMO_GROUP, n)
        if os.path.exists(p):
            return p
    if os.path.isdir(SUMO_GROUP):
        lnames = [c.lower() for c in candidates]
        for f in os.listdir(SUMO_GROUP):
            if f.lower() in lnames:
                return os.path.join(SUMO_GROUP, f)
    return None


def plate_for(pidx, vidx): return f"P{pidx+1}-{vidx+1:02d}"
def vid_for(pidx, vidx):   return f"v_p{pidx+1}_{vidx+1}"


def lane_allows_cars(lane_id):
    try:
        allowed = traci.lane.getAllowed(lane_id)
    except Exception:
        return True
    if not allowed:
        return True
    return any(a in ("passenger", "car", "all") for a in allowed)


def edge_allows_cars(edge_id):
    try:
        lanes = traci.edge.getLaneNumber(edge_id)
    except Exception:
        return False
    for i in range(lanes):
        try:
            if lane_allows_cars(f"{edge_id}_{i}"):
                return True
        except Exception:
            continue
    return False


def choose_candidate_edges(max_needed=10):
    out = []
    try:
        edges = traci.edge.getIDList()
    except Exception:
        return out
    for e in edges:
        try:
            if edge_allows_cars(e) and not e.startswith(":"):
                out.append(e)
                if len(out) >= max_needed:
                    break
        except Exception:
            continue
    return out


def compute_merge_point(edge_a, edge_b, forward_dist=40.0):
    try:
        sa = traci.edge.getShape(edge_a); sb = traci.edge.getShape(edge_b)
    except Exception:
        return None
    if not sa or not sb:
        return None
    aend  = sa[-1]; bend = sb[-1]
    mx    = (aend[0] + bend[0]) / 2.0
    my    = (aend[1] + bend[1]) / 2.0
    dir_a = (aend[0] - sa[0][0], aend[1] - sa[0][1])
    dir_b = (bend[0] - sb[0][0], bend[1] - sb[0][1])
    dax   = dir_a[0] + dir_b[0]; day = dir_a[1] + dir_b[1]
    n     = math.hypot(dax, day) or 1.0
    return (mx + dax / n * forward_dist, my + day / n * forward_dist)


def safe_set_vehicle_route(vid, target_edges):
    try:
        if not target_edges or vid not in traci.vehicle.getIDList():
            return False
        curr = traci.vehicle.getRoadID(vid)
        if not curr:
            try:
                traci.vehicle.changeTarget(vid, target_edges[0]); return True
            except Exception:
                return False
        if curr == target_edges[0]:
            try:
                traci.vehicle.setRoute(vid, target_edges); return True
            except Exception:
                pass
        if curr in target_edges:
            try:
                traci.vehicle.setRoute(vid, target_edges[target_edges.index(curr):]); return True
            except Exception:
                pass
        try:
            traci.vehicle.changeTarget(vid, target_edges[0]); return True
        except Exception:
            return False
    except Exception:
        return False


def _call_grpc_fn(fn_names, *args, **kwargs):
    modules = [sumo_ops, grpc_client, platoon_ops, intra_ops, server_mod]
    for m in modules:
        if not m:
            continue
        for name in fn_names:
            try:
                fn = getattr(m, name, None)
                if callable(fn):
                    try:
                        return fn(*args, **kwargs)
                    except TypeError:
                        try:
                            return fn(*args)
                        except Exception:
                            try:
                                return fn()
                            except Exception:
                                continue
                    except Exception:
                        continue
            except Exception:
                continue
    return None


def rsu_auth_and_join(_, plate, pid=None, rsu_id=None):
    res = _call_grpc_fn(
        ["rsu_auth_and_join", "auth_and_join", "join_platoon", "join", "join_rsu"],
        plate, pid, rsu_id=rsu_id)
    if res:
        return res
    if rsu_id:
        safe_put(msg_q, f"[RSU {rsu_id}] auth/join request for {plate}")
    secret = int(plate.split("-")[1])
    vehicle_secret         = 3000 + secret
    manufacturer_signature = 4000 + secret
    print(f"Attempting registration for {plate}")
    commitment = register_vehicle(vehicle_secret, manufacturer_signature)
    print(f"Registration result for {plate}: commitment={commitment}")
    if commitment:
        safe_put(msg_q, f"[RSU] registered {plate} → commitment {commitment}")
        return commitment
    return pid or f"mock-{plate.split('-')[0]}"


def do_merge(_, leader, src, dst, rsu_id=None):
    res = _call_grpc_fn(
        ["do_merge", "merge", "merge_platoons", "request_merge", "sumo_merge"],
        leader, src, dst, rsu_id=rsu_id)
    if res:
        return res
    if rsu_id:
        safe_put(msg_q, f"[RSU {rsu_id}] merge: leader={leader} src={src} dst={dst}")
    class R:
        pass
    r = R(); r.ok = (src != dst); r.message = None
    return r


def do_leave(_, plate, rsu_id=None):
    res = _call_grpc_fn(
        ["do_leave", "leave", "leave_platoon", "request_leave", "sumo_leave"],
        plate, rsu_id=rsu_id)
    if res:
        return res
    if rsu_id:
        safe_put(msg_q, f"[RSU {rsu_id}] leave: {plate}")
    class R:
        pass
    r = R(); r.ok = True; return r


def resolve_side_spawn_edge(side_idx, edges_graph, candidate_edge):
    try:
        if not edges_graph:
            return candidate_edge
        key = "side1" if side_idx == 1 else "side2"
        for e in edges_graph.keys():
            if key in e:
                return e
        target_end = f"s{side_idx}b"; target_start = f"s{side_idx}a"
        for e, (fr, to) in edges_graph.items():
            if to == target_end or fr == target_start:
                return e
    except Exception:
        pass
    return candidate_edge


def _vid_election_value(vid):
    try:
        m = re.match(r"v_p(\d+)_(\d+)", vid)
        if m:
            return int(m.group(1)) * 100 + int(m.group(2))
    except Exception:
        pass
    return abs(hash(vid)) % 100000


def bully_elect_leader(candidates):
    if not candidates:
        return None
    for v in candidates:
        if v not in vid_confidence:
            try:
                vid_confidence[v] = float(random.random())
                safe_put(msg_q, f"[CONF] assigned {v} confidence={vid_confidence[v]:.3f}")
            except Exception:
                vid_confidence[v] = 0.0
    best = None; best_conf = -1.0; ties = []
    for v in candidates:
        try:
            c = float(vid_confidence.get(v, 0.0))
        except Exception:
            c = 0.0
        if c > best_conf + 1e-9:
            best_conf = c; best = v; ties = [v]
        elif abs(c - best_conf) <= 1e-9:
            ties.append(v)
    if len(ties) > 1:
        chosen = None; best_val = -1
        for v in ties:
            try:
                val = _vid_election_value(v)
                if val > best_val:
                    best_val = val; chosen = v
            except Exception:
                continue
        return chosen or best
    return best


def synchronize_platoon_to_leader(vids, leader_vid, lane_change_duration=2.0):
    try:
        _call_grpc_fn(["synchronize_platoon_to_leader", "sync_platoon", "sync"],
                      vids, leader_vid)
    except Exception:
        pass
    try:
        try:
            leader_speed = float(traci.vehicle.getSpeed(leader_vid))
        except Exception:
            leader_speed = LEADER_SPEED_MPS
        try:
            leader_lane = int(traci.vehicle.getLaneIndex(leader_vid))
        except Exception:
            leader_lane = 0
        for v in vids:
            try:
                traci.vehicle.setSpeedMode(v, 0)
            except Exception:
                pass
            try:
                traci.vehicle.changeLane(v, leader_lane, lane_change_duration)
            except Exception:
                pass
            try:
                traci.vehicle.setSpeed(v, leader_speed)
            except Exception:
                try:
                    traci.vehicle.slowDown(v, leader_speed, 1.0)
                except Exception:
                    pass
    except Exception:
        pass


def get_view_id():
    try:
        vids = traci.gui.getIDList()
        if vids:
            return vids[0]
    except Exception:
        pass
    for candidate in ("View #0", "View #1", "View 0", "MainView"):
        try:
            if candidate in traci.gui.getIDList():
                return candidate
        except Exception:
            continue
    return ""


def pick_merge_edges_for_vid(vid, main_route_edges, preferred_main="main_1"):
    try:
        res = _call_grpc_fn(
            ["pick_merge_edges_for_vid", "recommend_merge_route",
             "choose_merge_route"],
            vid, main_route_edges, preferred_main)
        if isinstance(res, list) and res:
            return res
    except Exception:
        pass
    try:
        if not main_route_edges:
            return main_route_edges
        if preferred_main in main_route_edges:
            return main_route_edges[main_route_edges.index(preferred_main):]
        try:
            curr = traci.vehicle.getRoadID(vid)
        except Exception:
            curr = None
        if curr and curr in main_route_edges:
            return main_route_edges[main_route_edges.index(curr):]
    except Exception:
        pass
    return main_route_edges


def _ensure_vehicle_speed_and_lane(vid, speed, lane=0, lane_change_time=1.5):
    try:
        if vid not in traci.vehicle.getIDList():
            return
        try:
            traci.vehicle.setSpeedMode(vid, 0)
        except Exception:
            pass
        try:
            traci.vehicle.setSpeed(vid, speed)
        except Exception:
            try:
                traci.vehicle.slowDown(vid, speed, 0.5)
            except Exception:
                pass
        try:
            traci.vehicle.changeLane(vid, lane, lane_change_time)
        except Exception:
            pass
    except Exception:
        pass


def _slowdown_platoon2_towards(leader_speed, gap):
    if gap <= 0.0:
        return
    decel        = min(6.0, max(0.5, gap * PLATOON2_SLOW_K))
    target_speed = max(PLATOON2_MIN_SPEED, leader_speed - decel)
    head_vid     = vid_for(1, 0)
    try:
        if head_vid in traci.vehicle.getIDList():
            try:
                traci.vehicle.setSpeedMode(head_vid, 0)
            except Exception:
                pass
            try:
                traci.vehicle.slowDown(head_vid, float(target_speed), 0.8)
            except Exception:
                try:
                    traci.vehicle.setSpeed(head_vid, float(target_speed))
                except Exception:
                    pass
            try:
                lead1 = vid_for(0, 0)
                if lead1 in traci.vehicle.getIDList():
                    traci.vehicle.changeLane(
                        head_vid, traci.vehicle.getLaneIndex(lead1), 1.0)
            except Exception:
                pass
    except Exception:
        pass


def _find_free_platoon_index(pids_map, vid_platoon_index_map, present_ids):
    for i in range(PLATOON_COUNT):
        if not any(vid_platoon_index_map.get(v) == i for v in present_ids):
            return i
    return max(list(pids_map.keys()) or [PLATOON_COUNT - 1]) + 1


# ============================================================
#  MAIN SIMULATION  — ZKP + CATS + Blockchain + DB vote log
# ============================================================

def main():
    # ----------------------------------------------------------
    # GUI overlay thread
    # ----------------------------------------------------------
    threading.Thread(target=overlay_thread, args=(msg_q, cmd_q),
                     daemon=True).start()

    if traci is None:
        safe_put(msg_q, "[ERROR] traci not found"); return

    # ----------------------------------------------------------
    # Blockchain setup  (non-fatal)
    # ----------------------------------------------------------
    blockchain_mgr = BlockchainManager()
    blockchain_mgr.setup()

    # ----------------------------------------------------------
    # DB vote logger setup (non-fatal)
    # ----------------------------------------------------------
    db_vote_logger = DBVoteLogger(DB_CONFIG)
    db_vote_logger.setup()

    # Paper security objects (Khan et al. IEEE TITS 2025)
    ca = CertificationAuthority()
    vehicle_identity_managers: Dict[str, VehicleIdentityManager] = {}
    security_validator = SecurityPropertiesValidator()
    formation_calculator = PlatoonFormationCalculator()
    sec_logger = SecurityEventLogger()

    # ----------------------------------------------------------
    # SUMO config & binary
    # ----------------------------------------------------------
    try:
        cfg = ensure_sumocfg()
    except Exception as e:
        safe_put(msg_q, f"[ERROR] {e}"); return

    sumo_bin = find_sumo_binary()
    if not sumo_bin:
        safe_put(msg_q, "[ERROR] SUMO binary not found"); return

    safe_put(msg_q, f"[SUMO] starting: {sumo_bin} -c {cfg} "
                    f"--step-length {STEP_LENGTH}")
    try:
        traci.start([sumo_bin, "-c", cfg, "--step-length", str(STEP_LENGTH)])
    except Exception as e:
        safe_put(msg_q, f"[ERROR] traci.start failed: {e}"); return

    try:
        traci.simulationStep(); time.sleep(SIM_SLEEP)
    except Exception:
        pass
    try:
        load_rsu_positions()
    except Exception:
        safe_put(msg_q, "[RSU] failed to load RSU POIs")
    try:
        traci.simulationStep(); time.sleep(SIM_SLEEP)
    except Exception:
        pass

    # ----------------------------------------------------------
    # Edge / route resolution
    # ----------------------------------------------------------
    all_edges = []
    try:
        all_edges = traci.edge.getIDList()
    except Exception:
        safe_put(msg_q, "[ERROR] failed to list edges")
    cand = choose_candidate_edges(50)

    main_edges = []
    if SELECTED_MAIN_EDGE in all_edges and edge_allows_cars(SELECTED_MAIN_EDGE):
        main_edges = [SELECTED_MAIN_EDGE]
    if not main_edges and cand:
        main_edges = cand[:2]
    if not main_edges and all_edges:
        main_edges = [e for e in all_edges if not e.startswith(":")][:1]

    side1_edge = ("side1_connector" if "side1_connector" in all_edges
                  else (cand[2] if len(cand) > 2
                        else (all_edges[1] if len(all_edges) > 1 else main_edges[0])))
    side2_edge = (SELECTED_SIDE2_EDGE
                  if SELECTED_SIDE2_EDGE in all_edges and edge_allows_cars(SELECTED_SIDE2_EDGE)
                  else (cand[3] if len(cand) > 3
                        else (all_edges[2] if len(all_edges) > 2 else main_edges[0])))

    try:
        existing_routes = traci.route.getIDList()
    except Exception:
        existing_routes = []
    try:
        net_path = find_file_in_sumogroup(["guindy.net.xml", "guindy.net"])
        edges_graph, outs = ({}, {}) if not net_path else parse_net_graph(net_path)
        main_start  = main_edges[0] if main_edges else (cand[0] if cand else None)
        side1_start = side1_edge; side2_start = side2_edge
        if edges_graph and main_start:
            r_main_edges  = build_connected_route_from_net(
                main_start,  edges_graph, outs, 6) or [main_start]
            r_side1_edges = build_connected_route_from_net(
                side1_start, edges_graph, outs, 4) or [side1_start]
            r_side2_edges = build_connected_route_from_net(
                side2_start, edges_graph, outs, 4) or [side2_start]
        else:
            r_main_edges  = [e for e in cand[:4] if not e.startswith(":")] \
                            if cand else ([main_start] if main_start else [])
            r_side1_edges = [side1_start] if side1_start and not side1_start.startswith(":") else []
            r_side2_edges = [side2_start] if side2_start and not side2_start.startswith(":") else []
        if r_main_edges  and "r_main"  not in existing_routes:
            traci.route.add("r_main",  r_main_edges)
            safe_put(msg_q, f"[SUMO] r_main edges: {r_main_edges}")
        if r_side1_edges and "r_side1" not in existing_routes:
            traci.route.add("r_side1", r_side1_edges)
        if r_side2_edges and "r_side2" not in existing_routes:
            traci.route.add("r_side2", r_side2_edges)
    except Exception as e:
        safe_put(msg_q, f"[SUMO] failed to create runtime routes: {e}")

    # ----------------------------------------------------------
    # Spawn platoon-1 vehicles
    # ----------------------------------------------------------
    vid_to_plate       = {}
    vid_to_pid         = {}
    vid_platoon_index  = {}
    try:
        existing_vehicles = set(traci.vehicle.getIDList())
    except Exception:
        existing_vehicles = set()

    for vidx in range(PLATOON_SIZES[0]):
        vid    = vid_for(0, vidx)
        plate  = plate_for(0, vidx)
        depart = str(DEPART_BASE + vidx * DEPART_GAP)
        if vid in existing_vehicles:
            safe_put(msg_q, f"[SUMO] {vid} already present; skipping add")
        else:
            try:
                traci.vehicle.add(vid, "r_main", typeID="car", depart=depart)
            except Exception:
                try:
                    traci.vehicle.add(vid, "r_main", depart=depart)
                except Exception:
                    try:
                        e0 = main_edges[0] if main_edges else None
                        if e0:
                            traci.vehicle.add(vid, e0, depart=depart)
                    except Exception as e_final:
                        safe_put(msg_q, f"[SUMO] failed to add {vid}: {e_final}")
                        continue
        vid_to_plate[vid]      = plate
        vid_to_pid[vid]        = None
        vid_platoon_index[vid] = 0
        try:
            vid_confidence[vid] = float(random.random())
            safe_put(msg_q, f"[CONF] {vid} confidence={vid_confidence[vid]:.3f}")
        except Exception:
            pass
        try:
            _ensure_vehicle_speed_and_lane(vid, LEADER_SPEED_MPS, 0, 1.0)
        except Exception:
            pass

    # ----------------------------------------------------------
    # Junction markers
    # ----------------------------------------------------------
    junction1 = junction2 = None
    try:
        main_shape = []
        for e in main_edges:
            try:
                s = traci.edge.getShape(e)
                if s:
                    main_shape += s
            except Exception:
                pass
        if main_shape:
            ln   = len(main_shape)
            idx1 = max(1, int(ln * 0.30))
            idx2 = max(1, int(ln * 0.60))
            junction1 = main_shape[idx1] if idx1 < ln else main_shape[-1]
            junction2 = main_shape[idx2] if idx2 < ln else main_shape[-1]
            safe_put(msg_q, f"[SUMO] junction1={junction1}, junction2={junction2}")
    except Exception:
        pass

    planned_side_spawns = {
        1: {"edge": "side1_connector", "junction": junction1, "spawned": False},
        2: {"edge": side2_edge,        "junction": junction2, "spawned": False},
    }

    colored: set = set()
    pids: Dict[int, Optional[str]] = {i: None for i in range(PLATOON_COUNT)}
    joined              = {}
    leader_reported     = {i: False for i in range(PLATOON_COUNT)}
    prev_highlighted: set = set()

    step             = 0
    merge_attempted  = False
    merged_done      = False
    middle_left_done = False
    merged_vids: List[str] = []

    view = get_view_id()
    try:
        traci.gui.trackVehicle(view, "v_p1_1")
        traci.gui.setZoom(view, 250.0)
    except Exception:
        pass

    # ----------------------------------------------------------
    # CATS trust system objects
    # ----------------------------------------------------------
    message_broker     = MessageBroker()
    verifier           = Verifier()
    reputation_manager = ReputationManager()
    trust_vehicle_mgr  = TrustVehicleManager()
    trust_logger       = SimulationLogger()
    trust_logger.initialize_log_file()

    cats_initialized_vehicles: set  = set()
    cats_window_start_time: float   = 0.0
    reputation_window_idx:  int     = 0

    # Track which vehicles had blockchain trust set (to avoid double-setting)
    blockchain_trust_set: set = set()

    safe_put(msg_q, "\n" + "=" * 70)
    safe_put(msg_q, "CATS + BLOCKCHAIN + PAPER SECURITY (Khan et al. 2025) ACTIVE")
    safe_put(msg_q, "  [CA] Pk=%s..." % ca.Pk[:24])
    safe_put(msg_q, "  [CA] PK_CA=%s..." % ca.get_current_pk()[:24])
    safe_put(msg_q, "  [CA] Key rotation every %ds sim" % CA_KEY_ROTATION_INTERVAL)
    safe_put(msg_q, "  [CA] Proof reuse window %ds" % CA_PROOF_TIMESTAMP_WINDOW)
    safe_put(msg_q, f"  Malicious vehicle    : {CATS_MALICIOUS_VEHICLE_ID}")
    safe_put(msg_q, f"  Blockchain           : {'ENABLED' if blockchain_mgr.enabled else 'DISABLED (offline)'}")
    safe_put(msg_q, f"  DB vote logging      : {'ENABLED' if db_vote_logger.enabled else 'DISABLED (offline)'}")
    safe_put(msg_q, f"  False obstacle attack: {CATS_FALSE_OBSTACLE_START_TIME}s — {CATS_FALSE_OBSTACLE_END_TIME}s")
    safe_put(msg_q, f"  Incorrect beacon     : {CATS_INCORRECT_BEACON_START_TIME}s — {CATS_INCORRECT_BEACON_END_TIME}s")
    safe_put(msg_q, "=" * 70 + "\n")

    # ==========================================================
    #  MAIN SIMULATION LOOP
    # ==========================================================
    try:
        while step < SIM_STEPS:

            # ---- command queue ----
            try:
                cmd = cmd_q.get_nowait()
            except queue.Empty:
                cmd = None
            if cmd == "quit_sim":
                safe_put(msg_q, "[CTRL] Quit requested"); break

            # ---- advance SUMO ----
            try:
                traci.simulationStep()
            except FatalTraCIError as fte:
                safe_put(msg_q, f"[ERROR] SUMO connection closed: {fte}"); break

            sim_time = step * STEP_LENGTH
            present  = set(traci.vehicle.getIDList())

            # Paper Alg1: CA key rotation
            # "CA will timely update PK/SK... old PKCA in network
#  may not be entertained" -> stale key = impersonation flag
            if ca.maybe_rotate_keys(sim_time):
                safe_put(msg_q, "[CA] Key rotated @t=%.1fs new=%s..."%(sim_time,ca.get_current_pk()[:16]))
                sec_logger.log_security(sim_time,"KEY_ROTATION","CA","new_pk=%s"%ca.get_current_pk()[:24])

            # Paper Alg2+3+4: Vehicle Identity and ZKP Auth
            # Alg2: register -> FIdv,PKv,SKv,Cert
            # Alg3: gen proof -> sm,x,w,Proof (ZK construction)
            # Alg4: CA verify -> True/False
            # VI.A soundness, VI.B completeness, VI.C ZK check
            # V.A platoon formation time Eq13-16
            for veh_id in list(present):
                if veh_id not in vehicle_identity_managers:
                    vim = VehicleIdentityManager(veh_id, ca)
                    vehicle_identity_managers[veh_id] = vim
                    result = vim.authenticate_with_ca(sim_time)
                    if result.accepted:
                        security_validator.check_soundness(
                            veh_id, result, True, sim_time)
                        reg = ca.get_registry_entry(vim.fake_id)
                        if reg and vim.latest_proof:
                            security_validator.check_zero_knowledge(
                                veh_id, vim.latest_proof, reg, sim_time)
                        sec_logger.log_auth(sim_time, veh_id,
                            vim.fake_id or "", result, vim.proof_gen_time_ms)
                        timing = formation_calculator.compute(veh_id, sim_time)
                        if timing:
                            timing.auth_time_T = vim.proof_gen_time_ms/1000.0
                            safe_put(msg_q,"[Formation] %s Sit=%d T=%.1fms D=%.1fm ft=%.3fs"%(veh_id,timing.situation,timing.auth_time_T*1000,timing.distance_D,timing.formation_time))
                            sec_logger.log_formation(sim_time, timing)
                    else:
                        security_validator.check_soundness(
                            veh_id, result, True, sim_time)
                        if vim.latest_proof:
                            security_validator.check_impersonation(
                                veh_id, vim.latest_proof, ca, sim_time)
                        sec_logger.log_auth(sim_time, veh_id,
                            vim.fake_id or "", result, vim.proof_gen_time_ms)
                        safe_put(msg_q,"[CA] REJECTED %s: %s"%(veh_id,result.reason))

            # ==================================================
            # STEP 1 — ZKP registration / platoon join
            #   (done FIRST so commitment is available for CATS init)
            # ==================================================
            for vid, plate in list(vid_to_plate.items()):
                if vid in present and not joined.get(vid, False):
                    pidx          = vid_platoon_index[vid]
                    requested_pid = pids.get(pidx)
                    rsu_id        = get_nearest_rsu_for_vid(vid)

                    _vj=vehicle_identity_managers.get(vid)
                    if not security_validator.record_message(
                            vid, sim_time,
                            _vj.is_authenticated if _vj else False):
                        safe_put(msg_q,"[DDoS] %s rate-limited @t=%.1fs"%(vid,sim_time))
                        continue
                    pid = _call_grpc_fn(
                        ["rsu_auth_and_join", "auth_and_join",
                         "join_platoon", "join", "join_rsu"],
                        plate, requested_pid, rsu_id=rsu_id)
                    if not pid:
                        pid = rsu_auth_and_join(None, plate,
                                                pid=requested_pid, rsu_id=rsu_id)

                    if pid:
                        joined[vid] = True
                        # ------------------------------------------
                        # Store commitment mapping
                        # ------------------------------------------
                        vid_to_commitment[vid] = str(pid)

                        if pids.get(pidx) is None:
                            pids[pidx] = pid
                            safe_put(msg_q,
                                     f"[RSU {rsu_id or '?'}] Platoon {pidx} "
                                     f"created pid={pid} by {plate}")
                        else:
                            if requested_pid is None and pid != pids[pidx]:
                                pids[pidx] = pid

                        safe_put(msg_q,
                                 f"[RSU {rsu_id or '?'}] {plate} joined "
                                 f"pid={pids[pidx]}")

                        # ------------------------------------------
                        # BLOCKCHAIN: set initial trust score = 80
                        #   (called once per vehicle at login)
                        # ------------------------------------------
                        if vid not in blockchain_trust_set:
                            safe_put(msg_q,
                                     f"[Blockchain] Setting initial trust "
                                     f"score=80 for {vid} (commitment={pid})")
                            blockchain_mgr.set_initial_trust_score(
                                vid, str(pid),
                                score=int(CATS_BLOCKCHAIN_INIT_SCORE))
                            blockchain_trust_set.add(vid)

                    if (vid.endswith("_1")
                            and joined.get(vid, False)
                            and not leader_reported.get(pidx, False)):
                        leader_reported[pidx] = True

            # ==================================================
            # STEP 2 — CATS: initialise new vehicles
            #   Query blockchain for initial trust score;
            #   use 80 from blockchain or fallback to 70 (offline)
            # ==================================================
            for veh_id in present:
                if veh_id not in cats_initialized_vehicles:
                    message_broker.initialize_vehicle(veh_id)

                    # Try blockchain score first
                    blockchain_score = blockchain_mgr.get_initial_trust_score(veh_id)

                    # If blockchain gave nothing yet, check if we already
                    # set it (race condition guard — try once more)
                    if blockchain_score is None and veh_id in blockchain_trust_set:
                        blockchain_score = blockchain_mgr.get_initial_trust_score(
                            veh_id)

                    reputation_manager.initialize_vehicle(
                        veh_id, initial_score=blockchain_score)
                    cats_initialized_vehicles.add(veh_id)

                # Update trust-side state cache every step
                trust_vehicle_mgr.update_vehicle_state(veh_id, sim_time)

            # Handle late-registration: vehicle was CATS-inited with
            # fallback 70.0 but blockchain set score afterwards
            for veh_id in list(cats_initialized_vehicles):
                if (veh_id in blockchain_trust_set
                        and abs(reputation_manager.get_reputation(veh_id)
                                - CATS_INITIAL_REPUTATION) < 0.01):
                    bc_score = blockchain_mgr.get_initial_trust_score(veh_id)
                    if bc_score is not None and bc_score != CATS_INITIAL_REPUTATION:
                        reputation_manager.override_score(veh_id, bc_score)

            # ==================================================
            # STEP 3 — CATS: broadcast beacon messages (50 Hz)
            # ==================================================
            for veh_id in present:
                if not trust_vehicle_mgr.should_send_beacon(veh_id, sim_time):
                    continue
                real_state = trust_vehicle_mgr.get_vehicle_state(veh_id)
                if real_state is None:
                    continue
                _vb=vehicle_identity_managers.get(veh_id)
                if not security_validator.record_message(
                        veh_id, sim_time,
                        _vb.is_authenticated if _vb else False):
                    continue
                malicious_state = trust_vehicle_mgr.get_malicious_behavior(
                    veh_id, sim_time, real_state)
                state_to_broadcast = malicious_state if malicious_state \
                    else real_state
                beacon = BeaconMessage(
                    sender_id    = veh_id,
                    timestamp    = sim_time,
                    seq_no       = message_broker.get_next_seq_no(veh_id),
                    lane         = state_to_broadcast['lane'],
                    position     = state_to_broadcast['position'],
                    speed        = state_to_broadcast['speed'],
                    acceleration = state_to_broadcast['acceleration'],
                )
                message_broker.broadcast_message(
                    beacon, real_state['position'],
                    trust_vehicle_mgr.vehicle_states)
                verifier.update_previous_state(veh_id, real_state)

            # ==================================================
            # STEP 4 — CATS: broadcast obstacle messages
            # ==================================================
            for veh_id in present:
                state = trust_vehicle_mgr.get_vehicle_state(veh_id)
                if state is None:
                    continue
                if trust_vehicle_mgr.should_send_false_obstacle(veh_id, sim_time):
                    obs_msg = ObstacleMessage(
                        sender_id         = veh_id,
                        timestamp         = sim_time,
                        seq_no            = message_broker.get_next_seq_no(veh_id),
                        obstacle_in_lane  = True,
                        obstacle_position = state['position'] + 50.0,
                        lane              = state['lane'],
                    )
                    message_broker.broadcast_message(
                        obs_msg, state['position'],
                        trust_vehicle_mgr.vehicle_states)
                    trust_logger.log_event(
                        sim_time, 'FALSE_OBSTACLE',
                        f"{veh_id} sent false obstacle at "
                        f"{obs_msg.obstacle_position:.1f}m")
                else:
                    for obstacle in CATS_OBSTACLES:
                        if (obstacle['lane'] == state['lane']
                                and obstacle['t_start'] <= sim_time
                                <= obstacle['t_end']):
                            obs_center = ((obstacle['pos_start']
                                           + obstacle['pos_end']) / 2)
                            if abs(state['position'] - obs_center) <= 100.0:
                                obs_msg = ObstacleMessage(
                                    sender_id         = veh_id,
                                    timestamp         = sim_time,
                                    seq_no            = message_broker.get_next_seq_no(veh_id),
                                    obstacle_in_lane  = True,
                                    obstacle_position = obs_center,
                                    lane              = state['lane'],
                                )
                                message_broker.broadcast_message(
                                    obs_msg, state['position'],
                                    trust_vehicle_mgr.vehicle_states)
                                break

            # ==================================================
            # STEP 5 — CATS: process messages → generate votes
            #          → queue each vote to DB logger
            # ==================================================
            for receiver_id in list(present):
                receiver_state = trust_vehicle_mgr.get_vehicle_state(receiver_id)
                if receiver_state is None:
                    continue
                for message in message_broker.get_inbox(receiver_id):
                    sender_state = trust_vehicle_mgr.get_vehicle_state(
                        message.sender_id)
                    if sender_state is None:
                        continue
                    vote, is_first_reporter = verifier.process_message(
                        receiver_id, message, receiver_state, sender_state)

                    # Add to in-memory reputation window
                    reputation_manager.add_vote(
                        message.sender_id, vote, is_first_reporter)

                    # Queue to DB (skip NO_VOTE to reduce noise)
                    if vote != VoteType.NO_VOTE:
                        target_commitment = vid_to_commitment.get(
                            message.sender_id, "")
                        db_vote_logger.queue_vote(
                            sim_time          = sim_time,
                            target_vid        = message.sender_id,
                            target_commitment = target_commitment,
                            voter_vid         = receiver_id,
                            vote_type         = vote,
                            message_type      = message.msg_type,
                            reason            = (
                                "false_obstacle" if vote == VoteType.SEVERE_DOWNVOTE
                                else "kinematic_check" if vote == VoteType.DOWNVOTE
                                else "verified"),
                        )

                message_broker.clear_inbox(receiver_id)

            # ==================================================
            # STEP 6 — CATS: every 1-second window
            #          update reputations → blockchain + DB + CSV
            # ==================================================
            if (sim_time - cats_window_start_time
                    >= CATS_REPUTATION_UPDATE_WINDOW):
                print(f"\n--- CATS | Time: {sim_time:.1f}s ---")

                for veh_id in list(cats_initialized_vehicles):
                    update_info = reputation_manager.update_reputation(veh_id)
                    if update_info:
                        trust_logger.log_reputation_update(sim_time, update_info)

                        trust_state = reputation_manager.get_trust_state(veh_id)
                        trust_vehicle_mgr.apply_trust_based_actions(
                            veh_id, trust_state)

                        # ---- BLOCKCHAIN: write updated reputation ----
                        commitment = vid_to_commitment.get(veh_id, "")
                        if commitment:
                            blockchain_mgr.update_reputation_on_chain(
                                commitment,
                                update_info['new_reputation'],
                                update_info['new_state'])

                            # Flag state transitions on-chain
                            if update_info['old_state'] != update_info['new_state']:
                                blockchain_mgr.add_flag_on_chain(
                                    commitment,
                                    update_info['new_state'].upper(),
                                    reputation_window_idx)
                                sec_logger.log_security(
                                    sim_time,"TRUST_STATE_CHANGE",veh_id,
                                    "%s->%s R:%.1f->%.1f"%(update_info["old_state"],update_info["new_state"],update_info["old_reputation"],update_info["new_reputation"]))

                        # ---- DB: queue reputation record ----
                        db_vote_logger.queue_reputation(
                            sim_time, veh_id, commitment, update_info)

                # CSV log
                for veh_id in list(cats_initialized_vehicles):
                    vehicle_state  = trust_vehicle_mgr.get_vehicle_state(veh_id)
                    reputation_val = reputation_manager.get_reputation(veh_id)
                    trust_state    = reputation_manager.get_trust_state(veh_id)
                    votes          = reputation_manager.get_votes(veh_id)
                    trust_logger.log_vehicle_data(
                        sim_time,
                        veh_id,
                        {'reputation': reputation_val,
                         'trust_state': trust_state},
                        vehicle_state,
                        votes,
                    )

                trust_logger.write_to_file()        # flush CSV
                db_vote_logger.flush()              # flush DB (votes + rep)
                sec_logger.flush()                  # flush security event CSV
                reputation_manager.clear_vote_window()
                cats_window_start_time = sim_time
                reputation_window_idx += 1

            # ==================================================
            # ZKP / PLATOON: edge highlighting
            # ==================================================
            try:
                current_edges: set = set()
                for v in present:
                    try:
                        eid = traci.vehicle.getRoadID(v)
                    except Exception:
                        eid = None
                    if eid:
                        current_edges.add(eid)
                for e in current_edges:
                    try:
                        traci.edge.setColor(e, (255, 160, 0, 255))
                    except Exception:
                        try:
                            traci.edge.setColor(e, [255, 160, 0, 255])
                        except Exception:
                            pass
                for e in list(prev_highlighted - current_edges):
                    if e in main_edges or e in (
                            planned_side_spawns[1]["edge"],
                            planned_side_spawns[2]["edge"]):
                        continue
                    try:
                        traci.edge.setColor(e, (0, 0, 0, 0))
                    except Exception:
                        pass
                prev_highlighted = current_edges
            except Exception:
                pass

            # ==================================================
            # ZKP / PLATOON: per-vehicle colour assignment
            # ==================================================
            try:
                for vid in present:
                    if vid in vid_platoon_index and vid not in colored:
                        pidx  = vid_platoon_index[vid]
                        color = PLATOON_COLORS[pidx % len(PLATOON_COLORS)]
                        try:
                            traci.vehicle.setColor(vid, color)
                        except Exception:
                            try:
                                traci.vehicle.setColor(vid, list(color))
                            except Exception:
                                pass
                        colored.add(vid)
            except Exception:
                pass

            # ==================================================
            # ZKP / PLATOON: side-platoon proximity spawn
            # ==================================================
            try:
                leader_vid = vid_for(0, 0)
                if leader_vid in present:
                    leader_pos = traci.vehicle.getPosition(leader_vid)
                    for side_idx in (1, 2):
                        ps = planned_side_spawns[side_idx]
                        if not ps["spawned"] and ps["junction"] is not None:
                            d = math.hypot(
                                leader_pos[0] - ps["junction"][0],
                                leader_pos[1] - ps["junction"][1])
                            if d <= JUNCTION_TRIGGER_DIST:
                                resolved_edge = ps.get("edge")
                                try:
                                    np = find_file_in_sumogroup(
                                        ["guindy.net.xml", "guindy.net"])
                                    eg, _ = ({}, {}) if not np else parse_net_graph(np)
                                    resolved_edge = resolve_side_spawn_edge(
                                        side_idx, eg, ps.get("edge"))
                                except Exception:
                                    resolved_edge = ps.get("edge")
                                safe_put(msg_q,
                                         f"[EVENT] main leader near junction"
                                         f"{side_idx} (d={d:.1f}) → spawning "
                                         f"Platoon {side_idx+1} from "
                                         f"{resolved_edge}")
                                for vidx in range(PLATOON_SIZES[side_idx]):
                                    vid    = vid_for(side_idx, vidx)
                                    plate  = plate_for(side_idx, vidx)
                                    depart_time = (sim_time + SPAWN_AHEAD_SEC
                                                   + vidx * DEPART_GAP)
                                    chosen_route = f"r_side{side_idx}"
                                    added_ok = False
                                    try:
                                        if chosen_route in traci.route.getIDList():
                                            traci.vehicle.add(vid, chosen_route,
                                                              depart=str(depart_time))
                                            added_ok = True
                                        else:
                                            if resolved_edge:
                                                tmp_r = (f"tmp_side{side_idx}_"
                                                         f"{vid}_"
                                                         f"{int(time.time()*1000)}")
                                                try:
                                                    traci.route.add(tmp_r, [resolved_edge])
                                                    traci.vehicle.add(vid, tmp_r,
                                                                      depart=str(depart_time))
                                                    added_ok = True
                                                except Exception:
                                                    pass
                                    except Exception:
                                        pass
                                    if not added_ok:
                                        try:
                                            se = resolved_edge or ps.get("edge")
                                            if se:
                                                traci.vehicle.add(vid, se,
                                                                  depart=str(depart_time))
                                                added_ok = True
                                        except Exception as e_add:
                                            safe_put(msg_q,
                                                     f"[SUMO] failed to spawn "
                                                     f"{vid}: {e_add}")
                                            continue
                                    vid_to_plate[vid]      = plate
                                    vid_to_pid[vid]        = None
                                    vid_platoon_index[vid] = side_idx
                                    try:
                                        vid_confidence[vid] = float(random.random())
                                        safe_put(msg_q,
                                                 f"[CONF] {vid} confidence="
                                                 f"{vid_confidence[vid]:.3f}")
                                    except Exception:
                                        pass
                                    try:
                                        if side_idx == 1:
                                            faster = min(
                                                LEADER_SPEED_MPS
                                                * PLATOON2_SPEED_MULTIPLIER, 30.0)
                                            _ensure_vehicle_speed_and_lane(
                                                vid, faster, 1, 1.0)
                                        else:
                                            _ensure_vehicle_speed_and_lane(
                                                vid, LEADER_SPEED_MPS, 0, 1.0)
                                    except Exception:
                                        pass
                                ps["spawned"] = True
            except Exception:
                pass

            # ==================================================
            # ZKP / PLATOON: forced side1 spawn
            # ==================================================
            if (step == SIDE1_FORCE_SPAWN_STEP
                    and not planned_side_spawns[1]["spawned"]):
                safe_put(msg_q,
                         f"[FORCED] Step {step}: spawning Platoon-2 on "
                         f"'side1_connector' → 'main_1'")
                try:
                    start_edge   = "side1_connector"
                    forced_edges = [start_edge]
                    try:
                        main_route_edges = (traci.route.getEdges("r_main")
                                           if "r_main" in traci.route.getIDList()
                                           else main_edges[:])
                    except Exception:
                        main_route_edges = main_edges[:]
                    if "main_1" in main_route_edges:
                        idx = main_route_edges.index("main_1")
                        for me in main_route_edges[idx:]:
                            if me not in forced_edges:
                                forced_edges.append(me)
                    else:
                        for me in main_route_edges:
                            if me not in forced_edges:
                                forced_edges.append(me)
                except Exception:
                    forced_edges = ["side1_connector", "main_1", "main_2", "main_3"]

                tmp_rid = f"r_forced_side1_{int(time.time()*1000)}"
                try:
                    traci.route.add(tmp_rid, forced_edges)
                except Exception as e:
                    safe_put(msg_q, f"[SUMO] failed to add forced route: {e}")
                    tmp_rid = None

                for vidx in range(PLATOON_SIZES[1]):
                    vid   = vid_for(1, vidx)
                    plate = plate_for(1, vidx)
                    try:
                        if tmp_rid and tmp_rid in traci.route.getIDList():
                            traci.vehicle.add(vid, tmp_rid, typeID="car",
                                              depart=str(sim_time + 0.05))
                        else:
                            try:
                                traci.vehicle.add(vid, "side1_connector",
                                                  depart=str(sim_time + 0.05),
                                                  departPos="last")
                            except Exception:
                                traci.vehicle.add(vid, "side1_connector",
                                                  depart=str(sim_time + 0.05))
                        try:
                            if vid in traci.vehicle.getIDList():
                                traci.vehicle.setSpeedMode(vid, 0)
                                faster = min(
                                    LEADER_SPEED_MPS * PLATOON2_SPEED_MULTIPLIER,
                                    30.0)
                                try:
                                    traci.vehicle.setSpeed(vid, faster)
                                except Exception:
                                    traci.vehicle.slowDown(vid, faster, 0.5)
                                try:
                                    traci.vehicle.changeLane(vid, 1, 1.5)
                                except Exception:
                                    pass
                                try:
                                    traci.vehicle.changeTarget(vid, "main_1")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    except Exception as e_add:
                        safe_put(msg_q,
                                 f"[SUMO] forced spawn failed for {vid}: {e_add}")
                        continue
                    vid_to_plate[vid]      = plate
                    vid_to_pid[vid]        = None
                    vid_platoon_index[vid] = 1
                    try:
                        vid_confidence[vid] = float(random.random())
                        safe_put(msg_q,
                                 f"[CONF] {vid} confidence="
                                 f"{vid_confidence[vid]:.3f}")
                    except Exception:
                        pass

                planned_side_spawns[1]["spawned"] = True
                safe_put(msg_q,
                         f"[FORCED] Platoon-2 spawned on "
                         f"{forced_edges[:6]}"
                         f"{'...' if len(forced_edges) > 6 else ''}")

            # ==================================================
            # ZKP / PLATOON: proximity-based merge
            # ==================================================
            try:
                if (not merged_done) and (not merge_attempted):
                    p1_tail = vid_for(0, PLATOON_SIZES[0] - 1)
                    p2_head = vid_for(1, 0)
                    if p1_tail in present and p2_head in present:
                        p1_pos = traci.vehicle.getPosition(p1_tail)
                        p2_pos = traci.vehicle.getPosition(p2_head)
                        tail_to_head = math.hypot(
                            p1_pos[0] - p2_pos[0], p1_pos[1] - p2_pos[1])

                        if (step >= SLOW_START_STEP
                                and tail_to_head > MERGE_TARGET_DIST + MERGE_TOLERANCE):
                            try:
                                lead1        = vid_for(0, 0)
                                leader_speed = (float(traci.vehicle.getSpeed(lead1))
                                                if lead1 in traci.vehicle.getIDList()
                                                else LEADER_SPEED_MPS)
                            except Exception:
                                leader_speed = LEADER_SPEED_MPS
                            gap_excess = tail_to_head - MERGE_TARGET_DIST
                            if gap_excess > 0:
                                _slowdown_platoon2_towards(leader_speed, gap_excess)
                                print(f"[PLATOON] slowing P2 head "
                                      f"({tail_to_head:.1f}m → target {MERGE_TARGET_DIST}m)")

                        if (step >= MERGE_EXECUTE_STEP
                                and tail_to_head <= MERGE_TARGET_DIST + MERGE_TOLERANCE):
                            try:
                                lead1        = vid_for(0, 0)
                                leader_speed = (float(traci.vehicle.getSpeed(lead1))
                                                if lead1 in traci.vehicle.getIDList()
                                                else LEADER_SPEED_MPS)
                            except Exception:
                                leader_speed = LEADER_SPEED_MPS
                            for i in range(PLATOON_SIZES[1]):
                                vid = vid_for(1, i)
                                try:
                                    if vid in traci.vehicle.getIDList():
                                        traci.vehicle.slowDown(
                                            vid, float(leader_speed), 0.8)
                                        try:
                                            if vid_for(0, 0) in traci.vehicle.getIDList():
                                                lane_idx = traci.vehicle.getLaneIndex(
                                                    vid_for(0, 0))
                                                traci.vehicle.changeLane(
                                                    vid, lane_idx, 1.2)
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
                            safe_put(msg_q, f"[PLATOON] {p2_head} → requesting merge")
                            if pids.get(0) is None:
                                pids[0] = rsu_auth_and_join(None, plate_for(0, 0))
                            if pids.get(1) is None:
                                pids[1] = rsu_auth_and_join(None, plate_for(1, 0))
                            leader_plate   = plate_for(0, 0)
                            rsu_for_leader = get_nearest_rsu_for_vid(vid_for(0, 0))
                            resp = _call_grpc_fn(
                                ["do_merge", "merge", "merge_platoons",
                                 "request_merge", "sumo_merge"],
                                leader_plate, pids.get(0), pids.get(1),
                                rsu_id=rsu_for_leader)
                            do_merge(None, leader_plate,
                                     pids.get(0), pids.get(1))
                            if resp and getattr(resp, "ok", False):
                                merge_attempted = True
                            else:
                                safe_put(
                                    msg_q,
                                    f"[PLATOON] proximity merge rejected: "
                                    f"{getattr(resp, 'message', None)}")
                            merged_leader = _collect_and_force_recolour_merged(
                                0, pids, prefer_prefix="v_p2_")
                            if not merged_leader:
                                merged_vids = [
                                    v for v in traci.vehicle.getIDList()
                                    if vid_platoon_index.get(v) in (0, 1)
                                ] or [p1_tail, p2_head]
                                merged_leader = bully_elect_leader(merged_vids) or p1_tail
                                _apply_common_platoon_color(merged_vids, PLATOON_COLORS[0])
                                try:
                                    for v in merged_vids:
                                        vid_platoon_index[v] = 0
                                        vid_to_pid[v] = pids.get(0)
                                        colored.add(v)
                                except Exception:
                                    pass
                                try:
                                    view = get_view_id()
                                    if view:
                                        traci.gui.trackVehicle(view, merged_leader)
                                except Exception:
                                    pass
                            synchronize_platoon_to_leader(
                                [v for v in traci.vehicle.getIDList()
                                 if vid_platoon_index.get(v) == 0],
                                merged_leader)
                            merged_done = True
                            safe_put(msg_q,
                                     f"[PLATOON] merged: elected leader "
                                     f"{merged_leader}")
            except Exception:
                pass

            # ==================================================
            # ZKP / PLATOON: forced arrive-step merge prep
            # ==================================================
            if step == SIDE1_ARRIVE_STEP and not merge_attempted:
                p1_tail = vid_for(0, PLATOON_SIZES[0] - 1)
                p2_head = vid_for(1, 0)
                if (p1_tail in traci.vehicle.getIDList()
                        and p2_head in traci.vehicle.getIDList()):
                    try:
                        p1_pos = traci.vehicle.getPosition(p1_tail)
                        p2_pos = traci.vehicle.getPosition(p2_head)
                        tail_to_head = math.hypot(
                            p1_pos[0] - p2_pos[0], p1_pos[1] - p2_pos[1])
                    except Exception:
                        tail_to_head = 9999.0
                    try:
                        lead1        = vid_for(0, 0)
                        leader_speed = (float(traci.vehicle.getSpeed(lead1))
                                        if lead1 in traci.vehicle.getIDList()
                                        else LEADER_SPEED_MPS)
                    except Exception:
                        leader_speed = LEADER_SPEED_MPS
                    gap_excess = max(0.0, tail_to_head - MERGE_TARGET_DIST)
                    if gap_excess < 0:
                        _slowdown_platoon2_towards(leader_speed, gap_excess)
                        safe_put(msg_q,
                                 f"[FORCED-ARRIVE] Step {step}: P2 head slowed "
                                 f"({tail_to_head:.1f}m → {MERGE_TARGET_DIST}m)")
                    else:
                        safe_put(msg_q, "[PLATOON] FORCED merge rejected by server")

            # ==================================================
            # ZKP / PLATOON: mid-platoon leave + split at step 2300
            # ==================================================
            if step == 2300 and not middle_left_done:
                try:
                    chosen_vid  = None
                    chosen_pidx = None
                    for pidx in range(PLATOON_COUNT):
                        mid_vid = vid_for(pidx, 2)
                        if mid_vid in traci.vehicle.getIDList():
                            chosen_vid = mid_vid; chosen_pidx = pidx; break
                    if chosen_vid:
                        leave_plate = plate_for(chosen_pidx, 2)
                        leave_resp  = _call_grpc_fn(
                            ["do_leave", "leave", "leave_platoon",
                             "request_leave", "sumo_leave"],
                            leave_plate)
                        if leave_resp is None:
                            try:
                                do_leave(None, leave_plate)
                            except Exception:
                                pass
                        try:
                            old_sp = float(traci.vehicle.getSpeed(chosen_vid))
                        except Exception:
                            old_sp = LEADER_SPEED_MPS
                        new_sp = (min(old_sp * 1.2, 30.0)
                                  if step % 2 == 0
                                  else max(old_sp * 0.8, PLATOON2_MIN_SPEED))
                        target_lane = 3
                        try:
                            traci.vehicle.changeLane(chosen_vid, target_lane, 1.5)
                        except Exception:
                            try:
                                traci.vehicle.changeLane(chosen_vid, 1, 1.5)
                            except Exception:
                                pass
                        try:
                            traci.vehicle.slowDown(chosen_vid, float(new_sp), 2.4)
                        except Exception:
                            try:
                                traci.vehicle.setSpeed(chosen_vid, float(new_sp))
                            except Exception:
                                pass
                        try:
                            ids     = list(traci.vehicle.getIDList())
                            members = [v for v in ids
                                       if vid_platoon_index.get(v) == chosen_pidx]
                            try:
                                members.sort(
                                    key=lambda v:
                                    traci.vehicle.getPosition(v)[0],
                                    reverse=True)
                            except Exception:
                                pass
                            if chosen_vid in members:
                                idx    = members.index(chosen_vid)
                                ahead  = members[:idx]
                                behind = members[idx + 1:]
                            else:
                                ahead  = ([vid_for(chosen_pidx, 0)]
                                          if vid_for(chosen_pidx, 0) in ids else [])
                                behind = [v for v in members
                                          if v not in ahead and v != chosen_vid]
                            new_idx = _find_free_platoon_index(
                                pids, vid_platoon_index, ids)
                            if new_idx == chosen_pidx:
                                new_idx = (chosen_pidx + 1
                                           if chosen_pidx + 1 <= max(PLATOON_COUNT - 1,
                                                                     chosen_pidx)
                                           else chosen_pidx)
                            for v in ahead:
                                vid_platoon_index[v] = chosen_pidx
                            for v in behind:
                                vid_platoon_index[v] = new_idx
                            if behind:
                                first_plate = (vid_to_plate.get(behind[0])
                                               or plate_for(new_idx, 0))
                                new_pid = _call_grpc_fn(
                                    ["rsu_auth_and_join", "auth_and_join",
                                     "join_platoon", "join", "join_rsu"],
                                    first_plate, None)
                                if new_pid is None:
                                    new_pid = rsu_auth_and_join(
                                        None, first_plate, pid=None)
                                if new_idx not in pids:
                                    pids[new_idx] = None
                                pids[new_idx] = new_pid
                                for v in behind:
                                    vid_to_pid[v] = new_pid
                            vid_platoon_index[chosen_vid] = -1
                            vid_to_pid[chosen_vid]        = None
                            try:
                                ahead_color = PLATOON_COLORS[
                                    chosen_pidx % len(PLATOON_COLORS)]
                                new_color   = PLATOON_COLORS[
                                    new_idx % len(PLATOON_COLORS)]
                                for v in ahead:
                                    try:
                                        traci.vehicle.setColor(v, ahead_color)
                                    except Exception:
                                        try:
                                            traci.vehicle.setColor(v, list(ahead_color))
                                        except Exception:
                                            pass
                                for v in behind:
                                    try:
                                        traci.vehicle.setColor(v, new_color)
                                    except Exception:
                                        try:
                                            traci.vehicle.setColor(v, list(new_color))
                                        except Exception:
                                            pass
                                try:
                                    colored.update(ahead); colored.update(behind)
                                except Exception:
                                    for vv in ahead: colored.add(vv)
                                    for vv in behind: colored.add(vv)
                                try:
                                    traci.vehicle.setColor(chosen_vid, (160, 160, 160, 255))
                                    colored.add(chosen_vid)
                                except Exception:
                                    pass
                            except Exception:
                                pass
                            safe_put(
                                msg_q,
                                f"[LEAVE] step {step}: {chosen_vid} "
                                f"(was {old_sp:.2f} m/s) lane→{target_lane} "
                                f"speed→{new_sp:.2f} m/s; "
                                f"split platoon {chosen_pidx} → "
                                f"kept {len(ahead)} / new {len(behind)} idx {new_idx}")
                            try:
                                _call_grpc_fn(
                                    ["notify_platoon_split", "split_platoon",
                                     "platoon_split"],
                                    chosen_pidx, new_idx, ahead, behind)
                            except Exception:
                                pass
                        except Exception as e:
                            safe_put(msg_q, f"[LEAVE] split failed: {e}")
                        middle_left_done = True
                except Exception as e:
                    safe_put(msg_q, f"[LEAVE] step {step} failed: {e}")

            # ==================================================
            # ZKP / PLATOON: post-merge speed harmonisation
            # ==================================================
            if merged_done:
                cspeed = LEADER_SPEED_MPS * 0.95
                for vid in present:
                    try:
                        traci.vehicle.slowDown(vid, cspeed, 1.0)
                    except Exception:
                        pass

            # ==================================================
            # End-of-simulation check
            # ==================================================
            try:
                minexp      = traci.simulation.getMinExpectedNumber()
                present_now = len(traci.vehicle.getIDList())
                if minexp == 0 and present_now == 0:
                    safe_put(msg_q, "[SUMO] Simulation ended")
                    break
            except Exception:
                pass

            step += 1
            time.sleep(SIM_SLEEP)

            # ==================================================
            # Periodic console status (every 50 steps)
            # ==================================================
            if step % 50 == 0:
                try:
                    ids     = traci.vehicle.getIDList()
                    leaders = []
                    for p in range(PLATOON_COUNT):
                        lid = vid_for(p, 0)
                        if lid in ids:
                            pos = traci.vehicle.getPosition(lid)
                            leaders.append(f"{lid}={pos[0]:.1f},{pos[1]:.1f}")
                    if leaders:
                        print(f"[SUMO] step {step}/{SIM_STEPS} "
                              f"time={sim_time:.1f}s vehicles={len(ids)}")
                        print(" Leaders: " + " | ".join(leaders))
                except Exception:
                    print(f"[SUMO] step {step}/{SIM_STEPS} time={sim_time:.1f}s")

                for pidx in range(PLATOON_COUNT):
                    dists   = []
                    try:
                        ids = traci.vehicle.getIDList()
                    except Exception:
                        ids = []
                    members = [vid_for(pidx, i)
                                for i in range(PLATOON_SIZES[pidx])
                                if vid_for(pidx, i) in ids]
                    members += [v for v in ids
                                  if vid_platoon_index.get(v) == pidx
                                  and v not in members]
                    try:
                        members.sort(
                            key=lambda v: traci.vehicle.getPosition(v)[0],
                            reverse=True)
                    except Exception:
                        pass
                    for i in range(1, len(members)):
                        try:
                            pl = traci.vehicle.getPosition(members[i - 1])
                            pf = traci.vehicle.getPosition(members[i])
                            d  = math.hypot(pl[0] - pf[0], pl[1] - pf[1])
                            dists.append(f"{members[i-1]}→{members[i]}:{d:.1f}m")
                        except Exception:
                            dists.append(f"{members[i-1]}→{members[i]}:N/A")
                    if not dists:
                        print(f"[PLATOON] p{pidx+1} ({len(members)} members): "
                              f"no consecutive pairs")
                    else:
                        print(f"[PLATOON] p{pidx+1} distances: "
                              + " | ".join(dists))

    # ==========================================================
    # SIMULATION TEARDOWN
    # ==========================================================
    finally:
        # Final flush of any remaining buffered data
        trust_logger.write_to_file()
        db_vote_logger.flush()
        sec_logger.flush()

        try:
            traci.close()
        except Exception:
            pass
        safe_put(msg_q, "[SUMO] finished")
        safe_put(msg_q, "__QUIT__")

    # ----------------------------------------------------------
    # CATS: summary + plots
    # ----------------------------------------------------------
    trust_logger.print_summary(list(cats_initialized_vehicles),
                               reputation_manager)

    log_file = os.path.join(CATS_LOG_DIR, CATS_LOG_FILE)
    SimulationPlotter(log_file).generate_all_plots()

    # ----------------------------------------------------------
    # Blockchain: final reputation sync for all vehicles
    # ----------------------------------------------------------
    if blockchain_mgr.enabled:
        print("\n[Blockchain] Final on-chain reputation sync…")
        for veh_id in sorted(cats_initialized_vehicles):
            commitment = vid_to_commitment.get(veh_id, "")
            if not commitment:
                continue
            final_rep   = reputation_manager.get_reputation(veh_id)
            final_state = reputation_manager.get_trust_state(veh_id)
            blockchain_mgr.update_reputation_on_chain(
                commitment, final_rep, final_state)
            print(f"  {veh_id} → R={final_rep:.1f} ({final_state}) on-chain")

    security_validator.print_summary()
    formation_calculator.print_summary()
    if ca.proof_gen_times:
        avg_gen=sum(ca.proof_gen_times)/len(ca.proof_gen_times)
        avg_ver=(sum(ca.proof_verify_times)/len(ca.proof_verify_times) if ca.proof_verify_times else 0.0)
        print("\n"+"="*70)
        print("PROOF TIMING SUMMARY  Paper Section VII Fig 3 and 4")
        print("="*70)
        print("  Vehicles authenticated : %d"%len(ca.proof_gen_times))
        print("  Avg proof gen  (Fig 3) : %.3f ms"%avg_gen)
        print("  Avg verify     (Fig 4) : %.3f ms"%avg_ver)
        print("  Individual proofs - no Blockchain access during generation")
        print("  No waiting for other vehicles  (vs aggregate proof [ref 2])")
        print("="*70)
    print("\n[Main] Simulation complete! "
          "Check logs/ plots/ PostgreSQL and %s for results.\n" % SECURITY_LOG_FILE)


if __name__ == "__main__":
    main()