import threading
import time
import requests
import json
from functools import wraps

DASHBOARD_URL = "http://localhost:5050"
_SESSION = requests.Session()


# ─── Non-blocking HTTP fire-and-forget ────────────────────────────────────────

def _post(endpoint: str, data: dict):
    """Send event to dashboard without blocking the simulation loop."""
    def _send():
        try:
            _SESSION.post(f"{DASHBOARD_URL}{endpoint}", json=data, timeout=0.5)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


def _log_event(sim_time, event_type, detail="", **kwargs):
    _post("/event", {
        "sim_time": sim_time,
        "event_type": event_type,
        "detail": detail,
        **kwargs,
    })


# ─── Patch: CertificationAuthority ───────────────────────────────────────────

def _patch_ca(ca_class):
    """Patch CA.register_vehicle and CA.verify_proof to emit dashboard events."""

    orig_register = ca_class.register_vehicle
    def patched_register(self, real_id, sim_time):
        reg = orig_register(self, real_id, sim_time)
        _post("/event", {
            "sim_time": sim_time,
            "event_type": "CA_REGISTER",
            "detail": f"Vehicle {real_id} registered with CA",
            "vehicle_id": real_id,
            "fake_id": reg.fake_id[:20] + "..." if reg else "",
            "message": f"[CA] Registered {real_id} → FIdv={reg.fake_id[:12] if reg else '?'}...",
        })
        return reg
    ca_class.register_vehicle = patched_register

    orig_verify = ca_class.verify_proof
    def patched_verify(self, fake_id, proof):
        result = orig_verify(self, fake_id, proof)
        return result
    ca_class.verify_proof = patched_verify

    orig_rotate = ca_class.maybe_rotate_keys
    def patched_rotate(self, sim_time):
        rotated = orig_rotate(self, sim_time)
        if rotated:
            _post("/event", {
                "sim_time": sim_time,
                "event_type": "KEY_ROTATION",
                "detail": f"CA key rotated @ t={sim_time:.1f}s — new PK_CA={self.get_current_pk()[:16]}...",
                "message": f"[CA] Key rotated new={self.get_current_pk()[:16]}...",
            })
        return rotated
    ca_class.maybe_rotate_keys = patched_rotate


# ─── Patch: VehicleIdentityManager ───────────────────────────────────────────

def _patch_vim(vim_class):
    orig_auth = vim_class.authenticate_with_ca
    def patched_auth(self, sim_time):
        result = orig_auth(self, sim_time)
        # Send full commitment event with intermediate steps
        _post("/commitment", {
            "sim_time": sim_time,
            "vehicle_id": self.real_id,
            "fake_id": self.fake_id or "",
            "commitment": self.fake_id or "",       # fake_id IS the commitment handle
            "proof_gen_ms": self.proof_gen_time_ms,
            "verify_ms": result.verify_ms,
            "auth_status": "ACCEPTED" if result.accepted else "REJECTED",
            "reason": result.reason,
            # Intermediate steps for dashboard display
            "proof_sm": (self.latest_proof.sm[:16] + "...") if self.latest_proof else "",
            "proof_x":  (self.latest_proof.x[:16]  + "...") if self.latest_proof else "",
            "pk_ca":    (self.latest_proof.pk_ca[:16] + "...") if self.latest_proof else "",
        })
        return result
    vim_class.authenticate_with_ca = patched_auth


# ─── Patch: ReputationManager ─────────────────────────────────────────────────

def _patch_reputation(rep_class):
    orig_update = rep_class.update_reputation
    def patched_update(self, veh_id):
        update_info = orig_update(self, veh_id)
        if update_info:
            _post("/reputation", {
                "sim_time": getattr(self, '_last_sim_time', 0),
                "vehicle_id": veh_id,
                "old_reputation": update_info['old_reputation'],
                "new_reputation": update_info['new_reputation'],
                "reputation_change": update_info['reputation_change'],
                "old_state": update_info['old_state'],
                "new_state": update_info['new_state'],
                "upvotes": update_info['upvotes'],
                "downvotes": update_info['downvotes'],
                "severe_downvotes": update_info['severe_downvotes'],
                "reason": update_info['reason'],
            })
            # If state changed, also send a specific event
            if update_info['old_state'] != update_info['new_state']:
                _post("/event", {
                    "sim_time": getattr(self, '_last_sim_time', 0),
                    "event_type": "TRUST_STATE_CHANGE",
                    "vehicle_id": veh_id,
                    "old_state": update_info['old_state'],
                    "new_state": update_info['new_state'],
                    "detail": (f"{update_info['old_state']} → {update_info['new_state']} "
                               f"R:{update_info['old_reputation']:.1f}→{update_info['new_reputation']:.1f}"),
                })
        return update_info
    rep_class.update_reputation = patched_update


# ─── Patch: SecurityPropertiesValidator ──────────────────────────────────────

def _patch_security(spv_class):
    # Sybil detection
    orig_sybil = spv_class.check_sybil
    def patched_sybil(self, fake_real_id, attacker_phys_id, fake_id, was_accepted, sim_time):
        is_sybil = orig_sybil(self, fake_real_id, attacker_phys_id, fake_id, was_accepted, sim_time)
        if is_sybil:
            _post("/attack", {
                "sim_time": sim_time,
                "attack_type": "SYBIL",
                "vehicle_id": attacker_phys_id,
                "detail": (f"Sybil identity #{self._real_id_reg_count.get(attacker_phys_id,0)} "
                           f"detected — fake_id={fake_id[:12]}... blacklisted"),
                "fake_id": fake_id,
            })
        return is_sybil
    spv_class.check_sybil = patched_sybil

    # Spoofing detection
    orig_spoof = spv_class.check_spoofing
    def patched_spoof(self, vid, real_pos, reported_pos, reported_speed,
                      real_speed, sim_time, reputation_manager):
        is_spoofing = orig_spoof(self, vid, real_pos, reported_pos,
                                  reported_speed, real_speed, sim_time, reputation_manager)
        if is_spoofing:
            _post("/attack", {
                "sim_time": sim_time,
                "attack_type": "SPOOFING",
                "vehicle_id": vid,
                "detail": (f"GPS spoofing: reported={reported_pos:.1f}m real={real_pos:.1f}m "
                           f"dev={abs(reported_pos-real_pos):.1f}m speed={reported_speed:.1f}m/s"),
            })
        return is_spoofing
    spv_class.check_spoofing = patched_spoof

    # Impersonation
    orig_imp = spv_class.check_impersonation
    def patched_imp(self, vid, proof, ca, sim_time):
        suspected = orig_imp(self, vid, proof, ca, sim_time)
        if suspected:
            _post("/attack", {
                "sim_time": sim_time,
                "attack_type": "IMPERSONATION",
                "vehicle_id": vid,
                "detail": f"Stale/invalid PK_CA detected from {vid}",
            })
        return suspected
    spv_class.check_impersonation = patched_imp

    # DDoS
    orig_msg = spv_class.record_message
    def patched_msg(self, vid, sim_time, is_authenticated):
        ok = orig_msg(self, vid, sim_time, is_authenticated)
        if not ok:
            _post("/attack", {
                "sim_time": sim_time,
                "attack_type": "DDOS",
                "vehicle_id": vid,
                "detail": f"Rate-limit exceeded for unauthenticated {vid}",
            })
        return ok
    spv_class.record_message = patched_msg


# ─── Patch: BlockchainManager ─────────────────────────────────────────────────

def _patch_blockchain(bc_class):
    orig_set = bc_class.set_initial_trust_score
    def patched_set(self, vehicle_id, commitment, score=80):
        result = orig_set(self, vehicle_id, commitment, score)
        if result:
            _post("/blockchain", {
                "operation": "SET_TRUST_SCORE",
                "vehicle_id": vehicle_id,
                "commitment": str(commitment)[:20] + "..." if commitment else "",
                "score": score,
                "detail": f"VehicleTrust.setTrustScore({vehicle_id}, {score}) + CATS.updateReputation",
            })
        return result
    bc_class.set_initial_trust_score = patched_set

    orig_rep = bc_class.update_reputation_on_chain
    def patched_rep(self, commitment, score, trust_state_str):
        result = orig_rep(self, commitment, score, trust_state_str)
        if result:
            _post("/blockchain", {
                "operation": "UPDATE_REPUTATION",
                "commitment": str(commitment)[:20] + "...",
                "score": score,
                "trust_state": trust_state_str,
                "detail": f"CATS.updateReputation(score={score:.1f}, state={trust_state_str})",
            })
        return result
    bc_class.update_reputation_on_chain = patched_rep

    orig_flag = bc_class.add_flag_on_chain
    def patched_flag(self, commitment, flag_type, window_id):
        result = orig_flag(self, commitment, flag_type, window_id)
        if result:
            _post("/blockchain", {
                "operation": "ADD_FLAG",
                "flag_type": flag_type,
                "window_id": window_id,
                "detail": f"CATS.addFlag({flag_type}, window={window_id})",
            })
        return result
    bc_class.add_flag_on_chain = patched_flag


# ─── Patch: SimulationLogger (intercept safe_put → also send to dashboard) ───

def _patch_safe_put(module_globals: dict):
    """Patch safe_put so every msg_q message also appears in dashboard."""
    orig_safe_put = module_globals.get('safe_put')
    if not orig_safe_put:
        return

    def patched_safe_put(q, s):
        orig_safe_put(q, s)
        # Also broadcast to dashboard
        _post("/event", {
            "sim_time": 0,       # sim_time patched below via ReputationManager
            "event_type": _classify_msg(s),
            "detail": s,
            "message": s,
        })
    module_globals['safe_put'] = patched_safe_put


def _classify_msg(msg: str) -> str:
    m = str(msg).upper()
    if 'ATTACK' in m or 'SYBIL' in m or 'SPOOF' in m or 'DDOS' in m or 'IMPERSONATION' in m:
        return 'ATTACK'
    if 'BLOCKCHAIN' in m or 'ON-CHAIN' in m or 'CONTRACT' in m:
        return 'BLOCKCHAIN'
    if 'COMMIT' in m or 'ZKP' in m or 'PROOF' in m or 'AUTH' in m or 'CA]' in m:
        return 'COMMITMENT'
    if 'REPUTATION' in m or 'TRUST' in m or 'VOTE' in m:
        return 'REPUTATION'
    if 'FORMATION' in m:
        return 'FORMATION'
    if 'KEY ROTAT' in m or 'KEY_ROTAT' in m:
        return 'KEY_ROTATION'
    return 'LOG'


# ─── sim_time tracking on ReputationManager ──────────────────────────────────

def _patch_sim_time(rep_instance, sim_time: float):
    """Call this from the main loop to give ReputationManager current sim_time."""
    rep_instance._last_sim_time = sim_time


# ─── Public entry point ───────────────────────────────────────────────────────

def attach_dashboard(module_globals: dict = None):
    """
    Import and call this from sumo_attack.py:

        from dashboard_integration import attach_dashboard
        attach_dashboard(globals())

    It will:
    1. Start dashboard_server.py in a background daemon thread
    2. Monkey-patch all key classes to emit events
    """
    # 1. Start dashboard server
    def _run_server():
        import subprocess, sys
        import os
        server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "dashboard_server.py")
        try:
            subprocess.Popen(
                [sys.executable, server_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[Dashboard] Failed to start server: {e}")

    t = threading.Thread(target=_run_server, daemon=True)
    t.start()
    time.sleep(1.5)  # give Flask time to bind

    # 2. Patch classes — import them from the caller's globals or from module
    if module_globals is None:
        import sumo_attack as _m
        module_globals = vars(_m)

    _ca_class   = module_globals.get('CertificationAuthority')
    _vim_class  = module_globals.get('VehicleIdentityManager')
    _rep_class  = module_globals.get('ReputationManager')
    _spv_class  = module_globals.get('SecurityPropertiesValidator')
    _bc_class   = module_globals.get('BlockchainManager')

    if _ca_class:   _patch_ca(_ca_class)
    if _vim_class:  _patch_vim(_vim_class)
    if _rep_class:  _patch_reputation(_rep_class)
    if _spv_class:  _patch_security(_spv_class)
    if _bc_class:   _patch_blockchain(_bc_class)
    _patch_safe_put(module_globals)

    print("[Dashboard] ✓ Attached — open http://localhost:5050 in your browser")
    _post("/event", {
        "sim_time": 0,
        "event_type": "LOG",
        "detail": "Dashboard connected to simulation — streaming events",
    })


# ─── Helper to call from main loop ───────────────────────────────────────────

def update_sim_time(rep_instance, t: float):
    """Call once per CATS window: update_sim_time(reputation_manager, sim_time)"""
    _patch_sim_time(rep_instance, t)
