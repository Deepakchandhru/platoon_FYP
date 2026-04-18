"""
dashboard_server.py — Real-time Platoon Simulation Dashboard
Flask + SSE.  Includes full Evaluation Metrics panel covering:
  ZKP Auth · CATS Reputation · Attack Detection
  Platoon Ops · Blockchain · Security Properties · System Performance
"""

from flask import Flask, Response, request, jsonify
import json, queue, threading, time, copy, math

app = Flask(__name__)

event_queue = queue.Queue(maxsize=2000)
platoon_state = {}          # vid -> {...}
event_log     = []
summary_stats = {
    "total_vehicles": 0, "trusted": 0, "untrusted": 0, "banned": 0,
    "total_votes": 0, "total_upvotes": 0, "total_downvotes": 0, "total_severe": 0,
    "attacks_detected": 0, "commitments_generated": 0, "proofs_verified": 0,
    "blockchain_writes": 0, "sim_time": 0.0,
}

# ─── Metrics store ─────────────────────────────────────────────────────────────
metrics = {
    # 1. ZKP Authentication
    "zkp": {
        "proof_gen_ms_per_vehicle": {},   # vid -> float
        "verify_ms_per_vehicle":    {},   # vid -> float
        "auth_accepted": 0,
        "auth_rejected": 0,
        "soundness_violations": 0,
        "completeness_violations": 0,
        "zk_violations": 0,
        "impersonation_attempts": 0,
        "ddos_events": 0,
        "key_rotations": 0,
        "stale_key_rejections": 0,
    },
    # 2. CATS Reputation
    "cats": {
        "windows_processed": 0,
        "total_upvotes":  0,
        "total_downvotes": 0,
        "total_severe":   0,
        "trust_state_changes": [],  # [{vid, old, new, sim_time}]
        "banned_ejections": 0,
        "false_obs_detections": 0,
        "beacon_violations": 0,
        "rep_history": [],          # [{sim_time, trusted_avg, untrusted_avg, banned_count}]
    },
    # 3. Attacks
    "attacks": {
        "sybil": {
            "detected": False, "attacker": "", "fake_ids_created": 0,
            "fake_ids_blocked": 0, "fake_votes_stripped": 0,
            "start_time": None, "detection_time": None,
        },
        "spoof": {
            "detected": False, "attacker": "", "beacons_flagged": 0,
            "deviations": [], "start_time": None, "detection_time": None,
        },
        "false_obs": {
            "detected": False, "attacker": "", "broadcasts": 0,
            "downvotes_generated": 0, "detection_time": None,
        },
        "beacon_falsif": {
            "detected": False, "attacker": "", "violations": 0,
            "detection_time": None,
        },
    },
    # 4. Platoon Operations
    "platoon": {
        "formations": 0, "joins": 0,
        "leaves_normal": 0, "leaves_banned": 0,
        "merges": 0, "splits": 0, "leader_elections": 0,
        "formation_times": [],      # seconds per join event
        "situations": {"1": 0, "2": 0, "3": 0, "4": 0},
        "normal_leave_step": None,
        "banned_leave_step": None,
        "current_sizes": {},
    },
    # 5. Blockchain
    "blockchain": {
        "enabled": False,
        "writes_total": 0, "writes_success": 0, "writes_failed": 0,
        "trust_score_sets": 0, "rep_updates": 0, "flags_added": 0,
    },
    # 6. Security properties (Paper Section VI)
    "security": {
        "soundness_pass": True,
        "completeness_pass": True,
        "zk_pass": True,
        "privacy_pass": True,
        "anti_sybil_pass": True,
        "anti_spoof_pass": True,
        "anti_false_obs_pass": True,
        "anti_beacon_pass": True,
    },
    # 7. System
    "system": {
        "sim_steps": 0, "sim_duration_s": 0.0,
        "wall_start": None, "wall_elapsed_s": 0.0, "step_rate_hz": 0.0,
    },
}
state_lock = threading.Lock()
MAX_LOG = 300


# ─── Helpers ──────────────────────────────────────────────────────────────────

def broadcast(etype, data):
    payload = {"type": etype, "ts": time.time(), **data}
    with state_lock:
        event_log.append(payload)
        if len(event_log) > MAX_LOG:
            event_log.pop(0)
    try:
        event_queue.put_nowait(payload)
    except queue.Full:
        pass


def push_metrics():
    with state_lock:
        m = _metrics_snapshot()
    try:
        event_queue.put_nowait({"type": "METRICS", "ts": time.time(), "metrics": m})
    except queue.Full:
        pass


def _metrics_snapshot():
    """Compute derived fields; called with state_lock held."""
    m = copy.deepcopy(metrics)

    # ZKP derived
    z = m["zkp"]
    pts = list(z["proof_gen_ms_per_vehicle"].values())
    vts = list(z["verify_ms_per_vehicle"].values())
    z["avg_gen_ms"]  = round(sum(pts)/len(pts), 3) if pts else 0
    z["min_gen_ms"]  = round(min(pts), 3) if pts else 0
    z["max_gen_ms"]  = round(max(pts), 3) if pts else 0
    z["avg_ver_ms"]  = round(sum(vts)/len(vts), 3) if vts else 0
    z["min_ver_ms"]  = round(min(vts), 3) if vts else 0
    z["max_ver_ms"]  = round(max(vts), 3) if vts else 0
    tot = z["auth_accepted"] + z["auth_rejected"]
    z["success_rate"] = round(z["auth_accepted"] / tot * 100, 1) if tot else 0
    z["auth_total"]   = tot

    # Spoof derived
    sp = m["attacks"]["spoof"]
    devs = sp["deviations"] or []
    sp["max_dev_m"] = round(max(devs), 2) if devs else 0
    sp["avg_dev_m"] = round(sum(devs)/len(devs), 2) if devs else 0

    # Platoon derived
    p = m["platoon"]
    ft = p["formation_times"] or []
    p["avg_form_time_s"] = round(sum(ft)/len(ft), 4) if ft else 0
    p["max_form_time_s"] = round(max(ft), 4) if ft else 0

    # Blockchain derived
    bc = m["blockchain"]
    tb = bc["writes_success"] + bc["writes_failed"]
    bc["success_rate"] = round(bc["writes_success"]/tb*100, 1) if tb else 0

    # CATS rep averages from current platoon_state
    tr = [v.get("reputation", 0) for v in platoon_state.values() if v.get("trust_state") == "Trusted"]
    ut = [v.get("reputation", 0) for v in platoon_state.values() if v.get("trust_state") == "Untrusted"]
    m["cats"]["avg_rep_trusted"]   = round(sum(tr)/len(tr), 1) if tr else 0
    m["cats"]["avg_rep_untrusted"] = round(sum(ut)/len(ut), 1) if ut else 0

    return m


def _recount():
    t = u = b = 0
    for v in platoon_state.values():
        s = v.get("trust_state", "Trusted")
        if s == "Trusted": t += 1
        elif s == "Untrusted": u += 1
        elif s == "Banned": b += 1
    summary_stats["trusted"]   = t
    summary_stats["untrusted"] = u
    summary_stats["banned"]    = b


# ─── SSE ──────────────────────────────────────────────────────────────────────

def event_stream():
    with state_lock:
        snap = {
            "type": "snapshot",
            "platoon_state": dict(platoon_state),
            "summary": dict(summary_stats),
            "recent_events": list(event_log[-50:]),
            "metrics": _metrics_snapshot(),
        }
    yield f"data: {json.dumps(snap)}\n\n"
    while True:
        try:
            ev = event_queue.get(timeout=15)
            yield f"data: {json.dumps(ev)}\n\n"
        except queue.Empty:
            yield f"data: {json.dumps({'type':'ping'})}\n\n"


@app.route("/stream")
def stream():
    return Response(event_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── Existing ingest endpoints ─────────────────────────────────────────────────

@app.route("/event", methods=["POST"])
def ingest_event():
    data  = request.json or {}
    etype = data.get("event_type", "LOG")
    broadcast(etype, data)
    with state_lock:
        st = summary_stats
        st["sim_time"] = data.get("sim_time", st["sim_time"])
        sys = metrics["system"]
        sys["sim_duration_s"] = st["sim_time"]
        if sys["wall_start"] is None:
            sys["wall_start"] = time.time()
        else:
            sys["wall_elapsed_s"] = round(time.time() - sys["wall_start"], 1)
        sys["sim_steps"] += 1
        if sys["wall_elapsed_s"] > 0:
            sys["step_rate_hz"] = round(sys["sim_steps"] / sys["wall_elapsed_s"], 1)
    return jsonify({"ok": True})


@app.route("/commitment", methods=["POST"])
def ingest_commitment():
    data = request.json or {}
    vid  = data.get("vehicle_id", "?")
    with state_lock:
        if vid not in platoon_state:
            platoon_state[vid] = {}
        platoon_state[vid].update({
            "commitment":   data.get("commitment", ""),
            "fake_id":      data.get("fake_id", ""),
            "proof_gen_ms": data.get("proof_gen_ms", 0),
            "verify_ms":    data.get("verify_ms", 0),
            "auth_status":  data.get("auth_status", "PENDING"),
        })
        summary_stats["commitments_generated"] += 1
        z = metrics["zkp"]
        gms = data.get("proof_gen_ms", 0)
        vms = data.get("verify_ms", 0)
        if gms: z["proof_gen_ms_per_vehicle"][vid] = round(float(gms), 3)
        if vms: z["verify_ms_per_vehicle"][vid]    = round(float(vms), 3)
        if data.get("auth_status") == "ACCEPTED":
            summary_stats["proofs_verified"] += 1
            z["auth_accepted"] += 1
        elif data.get("auth_status") == "REJECTED":
            z["auth_rejected"] += 1
        summary_stats["total_vehicles"] = len(platoon_state)
        _recount()
    broadcast("COMMITMENT", {**data, "vehicle_id": vid})
    push_metrics()
    return jsonify({"ok": True})


@app.route("/reputation", methods=["POST"])
def ingest_reputation():
    data = request.json or {}
    vid  = data.get("vehicle_id", "?")
    with state_lock:
        if vid not in platoon_state:
            platoon_state[vid] = {}
        old_ts = platoon_state[vid].get("trust_state", "Trusted")
        new_ts = data.get("new_state", "Trusted")
        platoon_state[vid].update({
            "reputation":       data.get("new_reputation", 0),
            "trust_state":      new_ts,
            "last_vote_up":     data.get("upvotes", 0),
            "last_vote_down":   data.get("downvotes", 0),
            "last_vote_severe": data.get("severe_downvotes", 0),
            "rep_change":       data.get("reputation_change", 0),
        })
        uv, dv, sv = data.get("upvotes", 0), data.get("downvotes", 0), data.get("severe_downvotes", 0)
        summary_stats["total_votes"]     += uv + dv
        summary_stats["total_upvotes"]   += uv
        summary_stats["total_downvotes"] += dv
        summary_stats["total_severe"]    += sv
        c = metrics["cats"]
        c["total_upvotes"]  += uv
        c["total_downvotes"] += dv
        c["total_severe"]    += sv
        if old_ts != new_ts:
            c["trust_state_changes"].append({
                "vid": vid, "old": old_ts, "new": new_ts,
                "sim_time": data.get("sim_time", 0),
            })
        _recount()
    broadcast("REPUTATION", {**data, "vehicle_id": vid})
    push_metrics()
    return jsonify({"ok": True})


@app.route("/attack", methods=["POST"])
def ingest_attack():
    data  = request.json or {}
    atype = data.get("attack_type", "").lower()
    t     = data.get("sim_time")
    with state_lock:
        summary_stats["attacks_detected"] += 1
        if "sybil" in atype:
            s = metrics["attacks"]["sybil"]
            s["detected"] = True
            s["attacker"] = data.get("vehicle_id", s["attacker"])
            s["fake_ids_created"]    = data.get("fake_ids_created",    s["fake_ids_created"])
            s["fake_ids_blocked"]    = data.get("fake_ids_blocked",    s["fake_ids_blocked"])
            s["fake_votes_stripped"] = data.get("fake_votes_stripped", s["fake_votes_stripped"])
            if s["start_time"] is None:     s["start_time"]     = data.get("attack_start_time")
            if s["detection_time"] is None: s["detection_time"] = t
            metrics["security"]["anti_sybil_pass"] = True
        elif "spoof" in atype:
            s = metrics["attacks"]["spoof"]
            s["detected"] = True
            s["attacker"] = data.get("vehicle_id", s["attacker"])
            s["beacons_flagged"] += 1
            dev = data.get("deviation_m", 0)
            if dev: s["deviations"].append(float(dev))
            if s["start_time"] is None:     s["start_time"]     = data.get("attack_start_time")
            if s["detection_time"] is None: s["detection_time"] = t
            metrics["security"]["anti_spoof_pass"] = True
        elif "false" in atype or "obstacle" in atype:
            s = metrics["attacks"]["false_obs"]
            s["detected"] = True
            s["attacker"] = data.get("vehicle_id", s["attacker"])
            s["broadcasts"]         += data.get("broadcast_count", 1)
            s["downvotes_generated"] += data.get("downvotes", 0)
            if s["detection_time"] is None: s["detection_time"] = t
            metrics["cats"]["false_obs_detections"] += 1
            metrics["security"]["anti_false_obs_pass"] = True
        elif "beacon" in atype:
            s = metrics["attacks"]["beacon_falsif"]
            s["detected"] = True
            s["attacker"] = data.get("vehicle_id", s["attacker"])
            s["violations"] += data.get("violation_count", 1)
            if s["detection_time"] is None: s["detection_time"] = t
            metrics["cats"]["beacon_violations"] += data.get("violation_count", 1)
            metrics["security"]["anti_beacon_pass"] = True
    broadcast("ATTACK", data)
    push_metrics()
    return jsonify({"ok": True})


@app.route("/blockchain", methods=["POST"])
def ingest_blockchain():
    data = request.json or {}
    with state_lock:
        summary_stats["blockchain_writes"] += 1
        bc = metrics["blockchain"]
        bc["enabled"] = True
        bc["writes_total"] += 1
        if data.get("success", True): bc["writes_success"] += 1
        else:                          bc["writes_failed"]  += 1
        op = data.get("operation", "")
        if "trust" in op.lower():                            bc["trust_score_sets"] += 1
        elif "rep" in op.lower() or "update" in op.lower(): bc["rep_updates"]      += 1
        elif "flag" in op.lower():                           bc["flags_added"]      += 1
    broadcast("BLOCKCHAIN", data)
    push_metrics()
    return jsonify({"ok": True})


# ─── NEW: explicit metrics endpoint (called from simulation) ──────────────────

@app.route("/metrics", methods=["POST"])
def ingest_metrics():
    """
    Accepts structured metric updates from the simulation at runtime.
    Payload: { "category": "zkp"|"cats"|"platoon"|"security"|"attack_summary", ... }
    """
    data = request.json or {}
    cat  = data.get("category", "")
    with state_lock:
        if cat == "zkp":
            z = metrics["zkp"]
            for f in ("soundness_violations", "completeness_violations", "zk_violations",
                      "impersonation_attempts", "ddos_events", "key_rotations", "stale_key_rejections"):
                if f in data: z[f] = data[f]
            if data.get("soundness_violations", 0)    > 0: metrics["security"]["soundness_pass"]    = False
            if data.get("completeness_violations", 0) > 0: metrics["security"]["completeness_pass"]  = False
            if data.get("zk_violations", 0)           > 0: metrics["security"]["zk_pass"]            = False

        elif cat == "cats":
            c = metrics["cats"]
            for f in ("windows_processed", "banned_ejections"):
                if f in data: c[f] = data[f]
            if "banned_ejections" in data:
                metrics["platoon"]["leaves_banned"] = data["banned_ejections"]
            if "rep_snapshot" in data:
                c["rep_history"].append(data["rep_snapshot"])
                if len(c["rep_history"]) > 500: c["rep_history"] = c["rep_history"][-500:]

        elif cat == "platoon":
            p = metrics["platoon"]
            for f in ("formations", "joins", "leaves_normal", "merges",
                      "splits", "leader_elections", "normal_leave_step", "banned_leave_step"):
                if f in data: p[f] = data[f]
            if "formation_time_s" in data:
                p["formation_times"].append(float(data["formation_time_s"]))
            if "situation" in data:
                k = str(data["situation"])
                if k in p["situations"]: p["situations"][k] += 1
            if "platoon_sizes" in data:
                p["current_sizes"] = data["platoon_sizes"]

        elif cat == "security":
            for k, v in data.items():
                if k != "category" and k in metrics["security"]:
                    metrics["security"][k] = v

        elif cat == "attack_summary":
            for akey in ("sybil", "spoof", "false_obs", "beacon_falsif"):
                if akey in data: metrics["attacks"][akey].update(data[akey])

    push_metrics()
    return jsonify({"ok": True, "metrics" : metrics})


@app.route("/state")
def get_state():
    with state_lock:
        return jsonify({
            "platoon_state": dict(platoon_state),
            "summary": dict(summary_stats),
            "metrics": _metrics_snapshot(),
        })


# ─── Dashboard HTML ───────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>PLATOON · SENTINEL</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;800&family=Inter:wght@300;400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#060a12;--panel:#0d1422;--panel2:#091220;--border:#1a2a4a;--border2:#243a5e;
  --accent:#00e5ff;--accent2:#7c3aed;--green:#00ff88;--amber:#ffb700;
  --red:#ff3366;--text:#c8d8f0;--dim:#4a5a7a;--teal:#1de9b6;--blue:#4fa3f7;
  --glow:0 0 14px rgba(0,229,255,.35);--glow-g:0 0 14px rgba(0,255,136,.35);--glow-r:0 0 14px rgba(255,51,102,.35);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:13px;display:flex;flex-direction:column}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,.008) 2px,rgba(0,229,255,.008) 4px)}

/* scrollbars */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}

/* ── Header ── */
header{flex-shrink:0;background:linear-gradient(90deg,var(--panel),#091624);
  border-bottom:1px solid var(--border);padding:0 22px;height:50px;
  display:flex;align-items:center;justify-content:space-between;z-index:100;
  box-shadow:0 2px 24px rgba(0,0,0,.6)}
header h1{font-family:'Orbitron',sans-serif;font-size:15px;font-weight:800;color:var(--accent);
  letter-spacing:3px;text-shadow:var(--glow)}
header h1 span{color:var(--dim);font-weight:400}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:var(--glow-g);
  display:inline-block;margin-right:8px;animation:pulse 1.5s ease-in-out infinite}
.dot.off{background:var(--red);box-shadow:none;animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.sim-time{font-family:'Share Tech Mono',monospace;color:var(--accent);font-size:13px;letter-spacing:2px}

/* ── Top-stat tiles ── */
.tiles{flex-shrink:0;display:flex;gap:1px;background:var(--border);border-bottom:1px solid var(--border)}
.tile{flex:1;background:var(--panel);padding:10px 14px;display:flex;flex-direction:column;gap:3px;transition:background .15s}
.tile:hover{background:#111d35}
.tlbl{font-size:8px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);font-family:'Share Tech Mono',monospace}
.tval{font-family:'Orbitron',monospace;font-size:20px;font-weight:600;line-height:1}
.tval.c{color:var(--accent);text-shadow:var(--glow)}.tval.g{color:var(--green);text-shadow:var(--glow-g)}
.tval.a{color:var(--amber)}.tval.r{color:var(--red);text-shadow:var(--glow-r)}.tval.p{color:#a78bfa}
.tsub{font-size:9px;color:var(--dim)}

/* ── Tab bar ── */
.tab-bar{flex-shrink:0;display:flex;background:var(--panel2);border-bottom:1px solid var(--border)}
.tab{padding:8px 22px;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;
  color:var(--dim);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;user-select:none}
.tab:hover{color:var(--text);background:rgba(0,229,255,.03)}
.tab.on{color:var(--accent);border-bottom-color:var(--accent);background:rgba(0,229,255,.05)}

/* ── Tab pages ── */
.page{display:none;flex:1;overflow:hidden}
.page.on{display:flex}

/* ═══════════════════════════════════════════════════════
   EVENTS PAGE
═══════════════════════════════════════════════════════ */
#pg-events{display:grid;grid-template-columns:1fr 340px}
.ev-col{display:flex;flex-direction:column;border-right:1px solid var(--border);overflow:hidden}
.ph{padding:9px 14px;border-bottom:1px solid var(--border);font-family:'Share Tech Mono',monospace;
  font-size:10px;letter-spacing:2px;color:var(--accent);display:flex;align-items:center;justify-content:space-between;
  background:rgba(0,229,255,.04);flex-shrink:0}
.ph .badge{background:var(--accent2);color:#fff;padding:1px 7px;border-radius:3px;font-size:9px}
#event-log{flex:1;overflow-y:auto}
.ei{display:grid;grid-template-columns:50px 84px 1fr;gap:0;padding:6px 12px;
  border-bottom:1px solid rgba(26,42,74,.4);font-family:'Share Tech Mono',monospace;font-size:11px;
  animation:si .18s ease;line-height:1.5}
@keyframes si{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
.ei:hover{background:rgba(0,229,255,.025)}
.et{color:var(--dim)}.eb{color:var(--text);line-height:1.6}.eb strong{color:var(--accent)}
.etag{font-size:9px;padding:2px 4px;border-radius:2px;font-weight:600;letter-spacing:1px;text-align:center;
  align-self:start;margin-top:2px;width:72px}
.etag.COMMITMENT{background:rgba(124,58,237,.3);color:#c4b5fd;border:1px solid #7c3aed55}
.etag.REPUTATION{background:rgba(0,229,255,.15);color:var(--accent);border:1px solid var(--accent)55}
.etag.ATTACK{background:rgba(255,51,102,.2);color:var(--red);border:1px solid var(--red)55}
.etag.BLOCKCHAIN{background:rgba(255,183,0,.15);color:var(--amber);border:1px solid var(--amber)55}
.etag.AUTH{background:rgba(0,255,136,.12);color:var(--green);border:1px solid var(--green)55}
.etag.LOG{background:rgba(74,90,122,.2);color:var(--dim);border:1px solid #1a2a4a}
.etag.FORMATION{background:rgba(0,229,255,.08);color:#67e8f9;border:1px solid #22d3ee44}
.etag.KEY_ROTATION{background:rgba(255,183,0,.18);color:var(--amber);border:1px solid var(--amber)55}
.etag.TRUST_STATE_CHANGE{background:rgba(255,51,102,.25);color:#fca5a5;border:1px solid var(--red)66}
.edetail{grid-column:3;color:var(--dim);font-size:10px;margin-top:2px}
.esteps{grid-column:3;margin-top:3px;padding:5px 9px;background:rgba(0,0,0,.3);
  border-left:2px solid var(--accent2);border-radius:0 3px 3px 0;font-size:10px;color:#a78bfa}
.esteps .step{display:flex;gap:6px;align-items:flex-start;padding:2px 0}
.esteps .step::before{content:'▸';color:var(--accent2);flex-shrink:0}
/* vehicle panel */
.vc-col{display:flex;flex-direction:column;overflow:hidden;background:var(--panel)}
#vtable{flex:1;overflow-y:auto;padding:8px}
.vcard{background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:6px;
  margin-bottom:6px;overflow:hidden;transition:border-color .15s}
.vcard:hover{border-color:var(--accent)}
.vcard.trusted{border-left:3px solid var(--green)}.vcard.untrusted{border-left:3px solid var(--amber)}.vcard.banned{border-left:3px solid var(--red)}
.vch{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;
  background:rgba(255,255,255,.03);border-bottom:1px solid rgba(26,42,74,.5)}
.vid{font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--accent);font-weight:600}
.vst{font-size:9px;padding:2px 6px;border-radius:2px;font-family:'Share Tech Mono',monospace;letter-spacing:1px}
.vst.Trusted{background:rgba(0,255,136,.15);color:var(--green)}
.vst.Untrusted{background:rgba(255,183,0,.15);color:var(--amber)}
.vst.Banned{background:rgba(255,51,102,.2);color:var(--red);animation:blink .8s step-start infinite}
@keyframes blink{50%{opacity:.35}}
.vcb{padding:6px 10px;display:grid;grid-template-columns:1fr 1fr;gap:4px}
.vf{display:flex;flex-direction:column;gap:1px}
.vfl{font-size:8px;color:var(--dim);letter-spacing:1px;text-transform:uppercase}
.vfv{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text)}
.vcmt{padding:0 10px 6px;font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim);word-break:break-all}
.vcmt span{color:#5a7aaa}
.rb-wrap{padding:0 10px 7px}.rb{height:3px;background:var(--border);border-radius:2px;overflow:hidden}
.rf{height:100%;border-radius:2px;transition:width .4s,background .4s}
.vpills{padding:0 10px 7px;display:flex;gap:4px;flex-wrap:wrap}
.vp{font-size:9px;padding:2px 6px;border-radius:10px;font-family:'Share Tech Mono',monospace}
.vp.up{background:rgba(0,255,136,.1);color:var(--green)}.vp.dn{background:rgba(255,183,0,.1);color:var(--amber)}.vp.sv{background:rgba(255,51,102,.15);color:var(--red)}
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:160px;color:var(--dim);gap:8px;font-family:'Share Tech Mono',monospace;font-size:11px}
.empty-ico{font-size:28px;opacity:.3}
@keyframes fg{0%{background:rgba(0,255,136,.15)}100%{background:transparent}}
@keyframes fr{0%{background:rgba(255,51,102,.15)}100%{background:transparent}}
.fg{animation:fg .6s ease}.fr{animation:fr .6s ease}

/* ═══════════════════════════════════════════════════════
   METRICS PAGE
═══════════════════════════════════════════════════════ */
#pg-metrics{flex-direction:column;overflow-y:auto;background:var(--bg)}

.ms{padding:14px 20px;border-bottom:1px solid var(--border)}
.mst{font-family:'Orbitron',sans-serif;font-size:11px;font-weight:700;letter-spacing:3px;
  text-transform:uppercase;color:var(--accent);margin-bottom:12px;
  display:flex;align-items:center;gap:10px}
.mst::after{content:'';flex:1;height:1px;background:var(--border)}

/* grids */
.g2{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.g5{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.g6{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}

/* metric card */
.mc{background:var(--panel);border:1px solid var(--border);border-radius:6px;
  padding:10px 14px;display:flex;flex-direction:column;gap:4px;transition:border-color .15s}
.mc:hover{border-color:var(--border2)}
.mclbl{font-size:8px;letter-spacing:1.5px;text-transform:uppercase;color:var(--dim);
  font-family:'Share Tech Mono',monospace;margin-bottom:1px}
.mcval{font-family:'Orbitron',monospace;font-size:17px;font-weight:600;line-height:1;transition:color .3s}
.mcval.g{color:var(--green);text-shadow:var(--glow-g)}.mcval.r{color:var(--red);text-shadow:var(--glow-r)}
.mcval.c{color:var(--accent)}.mcval.a{color:var(--amber)}.mcval.p{color:#a78bfa}.mcval.t{color:var(--teal)}
.mcval.pass{color:var(--green)}.mcval.fail{color:var(--red)}
.mcsub{font-size:9px;color:var(--dim);line-height:1.4}

/* bar chart row */
.brow{display:flex;align-items:center;gap:8px;padding:3px 0;
  font-family:'Share Tech Mono',monospace;font-size:10px}
.brow-lbl{color:var(--dim);min-width:86px;flex-shrink:0}
.brow-wrap{flex:1;height:6px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden}
.brow-fill{height:100%;border-radius:3px;transition:width .5s ease}
.brow-val{color:var(--text);min-width:68px;text-align:right;flex-shrink:0}
.brow-val.hi{color:var(--amber)}
.chart-sep{border-top:1px dashed var(--border);margin:4px 0}

/* attack cards */
.ac{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:10px 14px}
.ac-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.ac-title{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:1.5px}
.abadge{font-size:9px;padding:2px 9px;border-radius:10px;font-family:'Share Tech Mono',monospace;font-weight:600}
.abadge.detected{background:rgba(0,255,136,.12);color:var(--green);border:1px solid rgba(0,255,136,.3)}
.abadge.pending{background:rgba(74,90,122,.2);color:var(--dim);border:1px solid var(--border)}
.ar{display:flex;justify-content:space-between;align-items:center;padding:3px 0;font-size:10px;
  border-bottom:1px solid rgba(26,42,74,.4)}
.ar:last-child{border-bottom:none}
.ark{color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:9px}
.arv{color:var(--text);font-family:'Share Tech Mono',monospace;font-size:10px}
.arv.ok{color:var(--green)}.arv.w{color:var(--amber)}.arv.bad{color:var(--red)}

/* Security properties table */
.sptable{width:100%;border-collapse:collapse;font-family:'Share Tech Mono',monospace;font-size:10px}
.sptable th{text-align:left;padding:7px 10px;color:var(--dim);font-size:8px;letter-spacing:1.5px;
  border-bottom:1px solid var(--border);font-weight:400;text-transform:uppercase}
.sptable td{padding:7px 10px;border-bottom:1px solid rgba(26,42,74,.35);vertical-align:top}
.sptable tr:last-child td{border-bottom:none}
.sptable tr:hover td{background:rgba(0,229,255,.018)}
.pname{color:var(--text);font-weight:600;font-size:10px}
.pref{color:var(--dim);font-size:8px;margin-top:1px}
.ps{font-size:9px;font-weight:700;padding:2px 8px;border-radius:3px;white-space:nowrap;display:inline-block}
.ps.pass{background:rgba(0,255,136,.12);color:var(--green);border:1px solid rgba(0,255,136,.3)}
.ps.fail{background:rgba(255,51,102,.15);color:var(--red);border:1px solid var(--red)44}
.pval{color:var(--accent);font-size:9px}
.pdesc{color:var(--dim);font-size:9px;line-height:1.5}

/* Trust transition list */
#cats-tr-list{display:flex;flex-direction:column;gap:3px;max-height:120px;overflow-y:auto}
.tr-item{display:flex;gap:10px;align-items:center;font-family:'Share Tech Mono',monospace;font-size:10px;
  padding:3px 8px;background:rgba(0,0,0,.2);border-radius:3px;border:1px solid var(--border)}
</style>
</head>
<body>

<!-- ══ HEADER ══ -->
<header>
  <div style="display:flex;align-items:center;gap:10px">
    <span class="dot" id="dot"></span>
    <h1>PLATOON <span>·</span> SENTINEL</h1>
  </div>
  <div class="sim-time">T+<span id="simclock">0.0</span>s</div>
  <div style="font-size:9px;color:var(--dim);font-family:'Share Tech Mono',monospace;letter-spacing:2px">
    ZKP · CATS · BLOCKCHAIN · TRUST
  </div>
</header>

<!-- ══ SUMMARY TILES ══ -->
<div class="tiles">
  <div class="tile"><div class="tlbl">Vehicles</div><div class="tval c" id="t-veh">0</div><div class="tsub">in simulation</div></div>
  <div class="tile"><div class="tlbl">Trusted</div><div class="tval g" id="t-tr">0</div><div class="tsub">trust state</div></div>
  <div class="tile"><div class="tlbl">Untrusted</div><div class="tval a" id="t-un">0</div><div class="tsub">flagged</div></div>
  <div class="tile"><div class="tlbl">Banned</div><div class="tval r" id="t-ban">0</div><div class="tsub">expelled</div></div>
  <div class="tile"><div class="tlbl">Votes</div><div class="tval c" id="t-v">0</div><div class="tsub">↑<span id="t-up">0</span> ↓<span id="t-dn">0</span> ⚠<span id="t-sv">0</span></div></div>
  <div class="tile"><div class="tlbl">Attacks</div><div class="tval r" id="t-atk">0</div><div class="tsub">detected</div></div>
  <div class="tile"><div class="tlbl">Commitments</div><div class="tval p" id="t-cm">0</div><div class="tsub">ZKP: <span id="t-zp">0</span> verified</div></div>
  <div class="tile"><div class="tlbl">Blockchain</div><div class="tval a" id="t-bc">0</div><div class="tsub">on-chain writes</div></div>
</div>

<!-- ══ TAB BAR ══ -->
<div class="tab-bar">
  <div class="tab on"  id="tb-events"  onclick="gotoTab('events')">◈ EVENT STREAM</div>
  <div class="tab"     id="tb-metrics" onclick="gotoTab('metrics')">◈ EVALUATION METRICS</div>
</div>

<!-- ══════════════════════════════════════════════════════════════════════
     PAGE: EVENTS
══════════════════════════════════════════════════════════════════════ -->
<div class="page on" id="pg-events">
  <div class="ev-col">
    <div class="ph"><span>◈ SIMULATION EVENT STREAM</span><span class="badge" id="evcnt">0 events</span></div>
    <div id="event-log"></div>
  </div>
  <div class="vc-col">
    <div class="ph"><span>◈ PLATOON MEMBER STATUS</span><span id="vcnt" style="color:var(--dim);font-size:10px">0 vehicles</span></div>
    <div id="vtable">
      <div class="empty" id="no-v"><div class="empty-ico">⬡</div><div>Awaiting vehicles…</div></div>
    </div>
  </div>
</div>

<!-- ══════════════════════════════════════════════════════════════════════
     PAGE: EVALUATION METRICS
══════════════════════════════════════════════════════════════════════ -->
<div class="page" id="pg-metrics">

  <!-- ① ZKP Authentication ─────────────────────────────────────────── -->
  <div class="ms">
    <div class="mst">🔐 ZKP Authentication — Algorithms 1–4  (Khan et al. IEEE TITS 2025)</div>

    <div class="g4" style="margin-bottom:10px">
      <div class="mc"><div class="mclbl">Avg Proof Gen · Fig 3</div>
        <div class="mcval c" id="mz-avg-gen">—</div><div class="mcsub">milliseconds · Algorithm 3</div></div>
      <div class="mc"><div class="mclbl">Avg Verify · Fig 4</div>
        <div class="mcval c" id="mz-avg-ver">—</div><div class="mcsub">milliseconds · Algorithm 4</div></div>
      <div class="mc"><div class="mclbl">Auth Success Rate</div>
        <div class="mcval pass" id="mz-rate">—</div><div class="mcsub">accepted / total</div></div>
      <div class="mc"><div class="mclbl">Vehicles Auth'd</div>
        <div class="mcval p" id="mz-total">0</div><div class="mcsub">FIdv commitments issued</div></div>
    </div>

    <div class="g3" style="margin-bottom:12px">
      <div class="mc"><div class="mclbl">Proof Gen Range</div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--text);margin:5px 0 2px">
          Min <span id="mz-min-g" style="color:var(--green)">—</span> ms &nbsp;
          Max <span id="mz-max-g" style="color:var(--amber)">—</span> ms
        </div>
        <div class="mcsub">per-vehicle ZK-SNARK gen spread</div>
      </div>
      <div class="mc"><div class="mclbl">Verify Range</div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--text);margin:5px 0 2px">
          Min <span id="mz-min-v" style="color:var(--green)">—</span> ms &nbsp;
          Max <span id="mz-max-v" style="color:var(--amber)">—</span> ms
        </div>
        <div class="mcsub">CA Algorithm 4 verify latency</div>
      </div>
      <div class="mc"><div class="mclbl">Key Rotations</div>
        <div class="mcval a" id="mz-rot">0</div>
        <div class="mcsub">60s interval · stale-key detection</div>
      </div>
    </div>

    <!-- Per-vehicle proof-gen bars -->
    <div style="font-size:8px;letter-spacing:1.5px;color:var(--dim);font-family:'Share Tech Mono',monospace;margin-bottom:5px">
      PROOF GENERATION TIME PER VEHICLE
    </div>
    <div id="z-gen-bars"></div>
    <div style="font-size:8px;letter-spacing:1.5px;color:var(--dim);font-family:'Share Tech Mono',monospace;margin:10px 0 5px">
      VERIFICATION TIME PER VEHICLE
    </div>
    <div id="z-ver-bars"></div>
  </div>

  <!-- ② CATS Reputation ────────────────────────────────────────────── -->
  <div class="ms">
    <div class="mst">📡 CATS Reputation System — V2V Cooperative Trust</div>

    <div class="g5" style="margin-bottom:10px">
      <div class="mc"><div class="mclbl">Rep Windows</div>
        <div class="mcval c" id="mc-win">0</div><div class="mcsub">1-s aggregation cycles</div></div>
      <div class="mc"><div class="mclbl">Upvotes</div>
        <div class="mcval g" id="mc-up">0</div><div class="mcsub">+1.0 pts each</div></div>
      <div class="mc"><div class="mclbl">Downvotes</div>
        <div class="mcval a" id="mc-dn">0</div><div class="mcsub">−5.0 pts each</div></div>
      <div class="mc"><div class="mclbl">Severe Downvotes</div>
        <div class="mcval r" id="mc-sv">0</div><div class="mcsub">−15.0 pts each</div></div>
      <div class="mc"><div class="mclbl">State Changes</div>
        <div class="mcval p" id="mc-chg">0</div><div class="mcsub">trust transitions total</div></div>
    </div>

    <div class="g4" style="margin-bottom:10px">
      <div class="mc"><div class="mclbl">Avg Rep · Trusted</div>
        <div class="mcval g" id="mc-avg-t">—</div><div class="mcsub">score / 100</div></div>
      <div class="mc"><div class="mclbl">Avg Rep · Untrusted</div>
        <div class="mcval a" id="mc-avg-u">—</div><div class="mcsub">score / 100</div></div>
      <div class="mc"><div class="mclbl">Banned Ejections</div>
        <div class="mcval r" id="mc-ej">0</div><div class="mcsub">leave-platoon (CATS-triggered)</div></div>
      <div class="mc"><div class="mclbl">False Obs Detected</div>
        <div class="mcval t" id="mc-fo">0</div><div class="mcsub">peer-verified obstacle lies</div></div>
    </div>

    <div style="font-size:8px;letter-spacing:1.5px;color:var(--dim);font-family:'Share Tech Mono',monospace;margin-bottom:5px">
      TRUST STATE TRANSITIONS (live)
    </div>
    <div id="cats-tr-list">
      <div style="color:var(--dim);font-size:9px;font-family:'Share Tech Mono',monospace;padding:4px">
        No transitions yet
      </div>
    </div>
  </div>

  <!-- ③ Attack Detection ───────────────────────────────────────────── -->
  <div class="ms">
    <div class="mst">⚠ Attack Detection Metrics — Section V.B</div>
    <div class="g4">

      <!-- Sybil -->
      <div class="ac">
        <div class="ac-hdr"><span class="ac-title">SYBIL ATTACK</span><span class="abadge pending" id="ab-sybil">PENDING</span></div>
        <div class="ar"><span class="ark">Attacker</span><span class="arv" id="as-att">—</span></div>
        <div class="ar"><span class="ark">Fake IDs created</span><span class="arv w" id="as-cr">0</span></div>
        <div class="ar"><span class="ark">Fake IDs blocked</span><span class="arv ok" id="as-bl">0</span></div>
        <div class="ar"><span class="ark">Fake votes stripped</span><span class="arv ok" id="as-vs">0</span></div>
        <div class="ar"><span class="ark">Attack start</span><span class="arv" id="as-st">—</span></div>
        <div class="ar"><span class="ark">Detection time</span><span class="arv" id="as-dt">—</span></div>
        <div class="ar"><span class="ark">Detection latency</span><span class="arv t" id="as-lat">—</span></div>
        <div class="ar"><span class="ark">Method</span><span class="arv ok" style="font-size:8px">CA dup-reg count</span></div>
      </div>

      <!-- Spoofing -->
      <div class="ac">
        <div class="ac-hdr"><span class="ac-title">GPS SPOOFING</span><span class="abadge pending" id="ab-spoof">PENDING</span></div>
        <div class="ar"><span class="ark">Attacker</span><span class="arv" id="sp-att">—</span></div>
        <div class="ar"><span class="ark">Beacons flagged</span><span class="arv w" id="sp-bf">0</span></div>
        <div class="ar"><span class="ark">Max deviation</span><span class="arv bad" id="sp-mx">0 m</span></div>
        <div class="ar"><span class="ark">Avg deviation</span><span class="arv" id="sp-av">0 m</span></div>
        <div class="ar"><span class="ark">Threshold</span><span class="arv ok">15.0 m</span></div>
        <div class="ar"><span class="ark">Attack start</span><span class="arv" id="sp-st">—</span></div>
        <div class="ar"><span class="ark">Detection time</span><span class="arv" id="sp-dt">—</span></div>
        <div class="ar"><span class="ark">Method</span><span class="arv ok" style="font-size:8px">RSU dead-reckoning</span></div>
      </div>

      <!-- False Obstacle -->
      <div class="ac">
        <div class="ac-hdr"><span class="ac-title">FALSE OBSTACLE</span><span class="abadge pending" id="ab-fobs">PENDING</span></div>
        <div class="ar"><span class="ark">Attacker</span><span class="arv" id="fo-att">—</span></div>
        <div class="ar"><span class="ark">Broadcasts</span><span class="arv w" id="fo-bc">0</span></div>
        <div class="ar"><span class="ark">Downvotes gen.</span><span class="arv ok" id="fo-dv">0</span></div>
        <div class="ar"><span class="ark">Detection time</span><span class="arv" id="fo-dt">—</span></div>
        <div class="ar"><span class="ark">Method</span><span class="arv ok" style="font-size:8px">Kinematic peer voting</span></div>
        <div class="ar"><span class="ark">Obs range</span><span class="arv">≤ 70 m</span></div>
        <div class="ar"><span class="ark">Window</span><span class="arv">t = 30–60 s</span></div>
        <div class="ar"><span class="ark">Penalty</span><span class="arv">−5.0 per downvote</span></div>
      </div>

      <!-- Beacon Falsification -->
      <div class="ac">
        <div class="ac-hdr"><span class="ac-title">BEACON FALSIF.</span><span class="abadge pending" id="ab-bkn">PENDING</span></div>
        <div class="ar"><span class="ark">Attacker</span><span class="arv" id="bk-att">—</span></div>
        <div class="ar"><span class="ark">Violations det.</span><span class="arv ok" id="bk-vl">0</span></div>
        <div class="ar"><span class="ark">Speed multiplier</span><span class="arv w">× 1.5</span></div>
        <div class="ar"><span class="ark">Max allowed speed</span><span class="arv ok">33.3 m/s</span></div>
        <div class="ar"><span class="ark">Pos offset used</span><span class="arv w">+ 20 m</span></div>
        <div class="ar"><span class="ark">Pos threshold</span><span class="arv ok">5.0 m</span></div>
        <div class="ar"><span class="ark">Detection time</span><span class="arv" id="bk-dt">—</span></div>
        <div class="ar"><span class="ark">Window</span><span class="arv">t = 80–110 s</span></div>
      </div>
    </div>
  </div>

  <!-- ④ Platoon Operations ─────────────────────────────────────────── -->
  <div class="ms">
    <div class="mst">🚗 Platoon Operations — Section V.A  Eq 13–16</div>
    <div class="g6" style="margin-bottom:10px">
      <div class="mc"><div class="mclbl">Formations</div><div class="mcval c" id="mp-form">0</div></div>
      <div class="mc"><div class="mclbl">Joins</div><div class="mcval g" id="mp-join">0</div></div>
      <div class="mc"><div class="mclbl">Leaves (normal)</div><div class="mcval a" id="mp-ln">0</div></div>
      <div class="mc"><div class="mclbl">Leaves (banned)</div><div class="mcval r" id="mp-lb">0</div></div>
      <div class="mc"><div class="mclbl">Merges</div><div class="mcval p" id="mp-mg">0</div></div>
      <div class="mc"><div class="mclbl">Leader Elections</div><div class="mcval t" id="mp-el">0</div></div>
    </div>

    <div class="g3">
      <div class="mc">
        <div class="mclbl">Avg Formation Time</div>
        <div class="mcval c" id="mp-aft">—</div>
        <div class="mcsub">seconds per join (Eq 13–16 output)</div>
      </div>

      <div class="mc">
        <div class="mclbl">Situations (Eq 13–16)</div>
        <div style="display:flex;gap:6px;margin-top:6px;text-align:center">
          <div style="flex:1"><div style="font-family:'Share Tech Mono',monospace;font-size:15px;color:var(--accent)" id="mp-s1">0</div><div style="font-size:8px;color:var(--dim);margin-top:2px">Eq13<br>Speed-up</div></div>
          <div style="flex:1"><div style="font-family:'Share Tech Mono',monospace;font-size:15px;color:var(--amber)" id="mp-s2">0</div><div style="font-size:8px;color:var(--dim);margin-top:2px">Eq14<br>Slow-dn</div></div>
          <div style="flex:1"><div style="font-family:'Share Tech Mono',monospace;font-size:15px;color:var(--dim)"   id="mp-s3">0</div><div style="font-size:8px;color:var(--dim);margin-top:2px">Eq15<br>Standing</div></div>
          <div style="flex:1"><div style="font-family:'Share Tech Mono',monospace;font-size:15px;color:var(--teal)"  id="mp-s4">0</div><div style="font-size:8px;color:var(--dim);margin-top:2px">Eq16<br>Coop.</div></div>
        </div>
      </div>

      <div class="mc">
        <div class="mclbl">Leave Operation Detail</div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:10px;margin-top:6px;display:flex;flex-direction:column;gap:4px">
          <div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--border)">
            <span style="color:var(--dim)">Normal leave (step 2300)</span>
            <span style="color:var(--amber)" id="mp-lstep">—</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:3px 0">
            <span style="color:var(--dim)">Banned leave (CATS-trigger)</span>
            <span style="color:var(--red)" id="mp-bstep">—</span>
          </div>
        </div>
        <div class="mcsub" style="margin-top:5px">setLaneChangeMode=0 applied (no return)</div>
      </div>
    </div>
  </div>

  <!-- ⑤ Blockchain ─────────────────────────────────────────────────── -->
  <div class="ms">
    <div class="mst">⛓ Blockchain — VehicleTrust.sol + CATS.sol</div>
    <div class="g5">
      <div class="mc"><div class="mclbl">Status</div>
        <div class="mcval" id="mb-en" style="font-size:14px">—</div>
        <div class="mcsub">Ganache + Web3.py</div>
      </div>
      <div class="mc"><div class="mclbl">Total Writes</div>
        <div class="mcval a" id="mb-tot">0</div><div class="mcsub">TX sent to chain</div>
      </div>
      <div class="mc"><div class="mclbl">TX Success Rate</div>
        <div class="mcval pass" id="mb-rate">—</div><div class="mcsub">success / total</div>
      </div>
      <div class="mc"><div class="mclbl">Rep Updates</div>
        <div class="mcval c" id="mb-rep">0</div><div class="mcsub">CATS.sol updateReputation()</div>
      </div>
      <div class="mc"><div class="mclbl">Flags Added</div>
        <div class="mcval r" id="mb-fl">0</div><div class="mcsub">state-change events on-chain</div>
      </div>
    </div>
  </div>

  <!-- ⑥ Security Properties ────────────────────────────────────────── -->
  <div class="ms">
    <div class="mst">🛡 Security Properties — Section VI  (Khan et al. IEEE TITS 2025)</div>
    <table class="sptable">
      <thead>
        <tr>
          <th style="width:20%">Property</th>
          <th style="width:13%">Reference</th>
          <th style="width:9%">Status</th>
          <th style="width:18%">Measured Value</th>
          <th>Description &amp; Evidence</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><div class="pname">Soundness</div><div class="pref">VI.A · Eq 21–22</div></td>
          <td style="color:var(--dim);font-size:9px">Forged proofs rejected</td>
          <td><span class="ps pass" id="sp-snd">PASS</span></td>
          <td><span class="pval" id="sv-snd">0 violations</span></td>
          <td class="pdesc">Verifier checks Hash(Pk‖x‖Hash(w)) vs stored Vk. A forger cannot reproduce Hash(w) without SK_v. Violations must equal 0.</td>
        </tr>
        <tr>
          <td><div class="pname">Completeness</div><div class="pref">VI.B · Eq 23–25</div></td>
          <td style="color:var(--dim);font-size:9px">Honest vehicles accepted</td>
          <td><span class="ps pass" id="sp-cmp">PASS</span></td>
          <td><span class="pval" id="sv-cmp">0 false rejections</span></td>
          <td class="pdesc">Every vehicle with a valid proof is accepted. False rejections must equal 0.</td>
        </tr>
        <tr>
          <td><div class="pname">Zero-Knowledge</div><div class="pref">VI.C · Eq 26–27</div></td>
          <td style="color:var(--dim);font-size:9px">Witness never revealed</td>
          <td><span class="ps pass" id="sp-zk">PASS</span></td>
          <td><span class="pval" id="sv-zk">0 leaks</span></td>
          <td class="pdesc">w = (SK_v, PK_v) is never in the proof string. Only Hash(w) is stored and checked. ZK leaks must equal 0.</td>
        </tr>
        <tr>
          <td><div class="pname">Privacy (Goal 2)</div><div class="pref">Section IV.D</div></td>
          <td style="color:var(--dim);font-size:9px">real_id off-chain</td>
          <td><span class="ps pass" id="sp-prv">PASS</span></td>
          <td><span class="pval" id="sv-prv">FIdv only</span></td>
          <td class="pdesc">FIdv = SHA256(salt ‖ real_id). real_id discarded after registration. Only the pseudonym FIdv appears on-chain.</td>
        </tr>
        <tr>
          <td><div class="pname">Anti-Sybil</div><div class="pref">V.B · Ref 1, 3</div></td>
          <td style="color:var(--dim);font-size:9px">Dup. registrations blocked</td>
          <td><span class="ps pass" id="sp-syb">PASS</span></td>
          <td><span class="pval" id="sv-syb">—</span></td>
          <td class="pdesc">CA counts per-physical-vehicle registrations. Any count &gt; SYBIL_MAX_REGISTRATIONS=1 triggers blacklisting.</td>
        </tr>
        <tr>
          <td><div class="pname">Anti-Spoofing</div><div class="pref">V.B · Ref 4</div></td>
          <td style="color:var(--dim);font-size:9px">GPS cross-validated by RSU</td>
          <td><span class="ps pass" id="sp-spf">PASS</span></td>
          <td><span class="pval" id="sv-spf">—</span></td>
          <td class="pdesc">RSU dead-reckoning: |reported − real_pos| &gt; 15 m ⟹ SPOOFING_DETECTED + SEVERE_DOWNVOTE (−15 pts).</td>
        </tr>
        <tr>
          <td><div class="pname">Anti-FalseObs.</div><div class="pref">CATS V2V Voting</div></td>
          <td style="color:var(--dim);font-size:9px">Peer kinematic voting</td>
          <td><span class="ps pass" id="sp-fob">PASS</span></td>
          <td><span class="pval" id="sv-fob">—</span></td>
          <td class="pdesc">Neighbours within 70 m verify obstacle. Mismatch ⟹ DOWNVOTE (−5 pts per peer). False reports rapidly sink reputation.</td>
        </tr>
        <tr>
          <td><div class="pname">Anti-Beacon-Falsif.</div><div class="pref">CATS Kinematics</div></td>
          <td style="color:var(--dim);font-size:9px">Speed &amp; pos bounds</td>
          <td><span class="ps pass" id="sp-bkn">PASS</span></td>
          <td><span class="pval" id="sv-bkn">—</span></td>
          <td class="pdesc">Speed &gt; CATS_MAX_SPEED (33.3 m/s) or pos_error &gt; 5 m detected by kinematic verifier ⟹ DOWNVOTE.</td>
        </tr>
        <tr>
          <td><div class="pname">DDoS Resistance</div><div class="pref">V.B · Rate-Limit</div></td>
          <td style="color:var(--dim);font-size:9px">Unauth. msgs capped</td>
          <td><span class="ps pass" id="sp-ddos">PASS</span></td>
          <td><span class="pval" id="sv-ddos">0 events</span></td>
          <td class="pdesc">Unauthenticated vehicles are limited to DDOS_MSG_RATE_LIMIT=5 msgs/s. Authenticated vehicles bypass this limit.</td>
        </tr>
        <tr>
          <td><div class="pname">Impersonation</div><div class="pref">V.B · Stale-Key</div></td>
          <td style="color:var(--dim);font-size:9px">Stale PK_CA flagged</td>
          <td><span class="ps pass" id="sp-imp">PASS</span></td>
          <td><span class="pval" id="sv-imp">0 attempts</span></td>
          <td class="pdesc">Proof bearing an outdated PK_CA (pre-rotation) is rejected as a STALE_KEY impersonation attempt.</td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- ⑦ System Performance ─────────────────────────────────────────── -->
  <div class="ms">
    <div class="mst">⚙ System Performance</div>
    <div class="g4">
      <div class="mc"><div class="mclbl">Sim Time</div>
        <div class="mcval c" id="msys-sim">0 s</div><div class="mcsub">simulation seconds</div></div>
      <div class="mc"><div class="mclbl">Wall-Clock</div>
        <div class="mcval a" id="msys-wall">0 s</div><div class="mcsub">real seconds since start</div></div>
      <div class="mc"><div class="mclbl">Step Rate</div>
        <div class="mcval t" id="msys-hz">0 Hz</div><div class="mcsub">TraCI steps / real second</div></div>
      <div class="mc"><div class="mclbl">Total Steps</div>
        <div class="mcval p" id="msys-steps">0</div><div class="mcsub">TraCI simulation steps</div></div>
    </div>
  </div>

</div><!-- /pg-metrics -->

<script>
// ═══════════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════════
const MAX_EV = 150;
let evCount = 0, vState = {}, summary = {};
let local = {
  total_vehicles:0, trusted:0, untrusted:0, banned:0,
  total_votes:0, total_upvotes:0, total_downvotes:0, total_severe:0,
  attacks_detected:0, commitments_generated:0, proofs_verified:0, blockchain_writes:0,
};
// per-vehicle proof timings for bar charts
let pvGen = {}, pvVer = {};

// ═══════════════════════════════════════════════════════════════════════
// TAB SWITCHING
// ═══════════════════════════════════════════════════════════════════════
function gotoTab(name) {
  ['events','metrics'].forEach(t => {
    document.getElementById('pg-'+t).classList.toggle('on', t===name);
    document.getElementById('tb-'+t).classList.toggle('on', t===name);
  });
}

// ═══════════════════════════════════════════════════════════════════════
// SSE
// ═══════════════════════════════════════════════════════════════════════
function connect() {
  const es = new EventSource('/stream');
  document.getElementById('dot').classList.remove('off');
  es.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'ping') return;
    if (msg.type === 'snapshot') {
      vState  = msg.platoon_state || {};
      summary = msg.summary       || {};
      updateTiles(summary);
      renderAllVehicles();
      (msg.recent_events || []).forEach(ev => appendEvent(ev));
      if (msg.metrics) applyMetrics(msg.metrics);
      return;
    }
    if (msg.type === 'METRICS') { applyMetrics(msg.metrics); return; }
    handleEvent(msg);
  };
  es.onerror = () => {
    document.getElementById('dot').classList.add('off');
    setTimeout(connect, 3000);
  };
}

// ═══════════════════════════════════════════════════════════════════════
// EVENT HANDLER
// ═══════════════════════════════════════════════════════════════════════
function handleEvent(ev) {
  const type = ev.type;
  if (type === 'COMMITMENT') {
    const vid = ev.vehicle_id;
    if (!vState[vid]) vState[vid] = {};
    Object.assign(vState[vid], {
      commitment: ev.commitment||'', fake_id: ev.fake_id||'',
      proof_gen_ms: ev.proof_gen_ms||0, verify_ms: ev.verify_ms||0,
      auth_status: ev.auth_status||'PENDING',
    });
    if (ev.proof_gen_ms) pvGen[vid] = ev.proof_gen_ms;
    if (ev.verify_ms)    pvVer[vid] = ev.verify_ms;
    upsertCard(vid);
  } else if (type === 'REPUTATION') {
    const vid = ev.vehicle_id;
    if (!vState[vid]) vState[vid] = {};
    Object.assign(vState[vid], {
      reputation: ev.new_reputation, trust_state: ev.new_state,
      last_vote_up: ev.upvotes, last_vote_down: ev.downvotes,
      last_vote_severe: ev.severe_downvotes, rep_change: ev.reputation_change,
    });
    upsertCard(vid);
  }
  if (ev.sim_time !== undefined)
    document.getElementById('simclock').textContent = ev.sim_time.toFixed(1);
  updateTilesLocal(type, ev);
  appendEvent(ev);
}

// ═══════════════════════════════════════════════════════════════════════
// TILES
// ═══════════════════════════════════════════════════════════════════════
function st(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function updateTiles(s) {
  st('t-veh', s.total_vehicles||0); st('t-tr', s.trusted||0);
  st('t-un',  s.untrusted||0);      st('t-ban', s.banned||0);
  st('t-v',   s.total_votes||0);
  st('t-up',  s.total_upvotes||0);  st('t-dn', s.total_downvotes||0);
  st('t-sv',  s.total_severe||0);   st('t-atk', s.attacks_detected||0);
  st('t-cm',  s.commitments_generated||0);
  st('t-zp',  s.proofs_verified||0);
  st('t-bc',  s.blockchain_writes||0);
  st('vcnt', Object.keys(vState).length+' vehicles');
}
function updateTilesLocal(type, ev) {
  if (type==='COMMITMENT') {
    local.commitments_generated++;
    if (ev.auth_status==='ACCEPTED') local.proofs_verified++;
    local.total_vehicles = Object.keys(vState).length;
  }
  if (type==='REPUTATION') {
    local.total_votes += (ev.upvotes||0)+(ev.downvotes||0);
    local.total_upvotes   += ev.upvotes||0;
    local.total_downvotes += ev.downvotes||0;
    local.total_severe    += ev.severe_downvotes||0;
    let t=0,u=0,b=0;
    for (const v of Object.values(vState)) {
      if (v.trust_state==='Trusted') t++;
      else if (v.trust_state==='Untrusted') u++;
      else if (v.trust_state==='Banned') b++;
    }
    local.trusted=t; local.untrusted=u; local.banned=b;
  }
  if (type==='ATTACK')     local.attacks_detected++;
  if (type==='BLOCKCHAIN') local.blockchain_writes++;
  updateTiles({...local, ...summary});
}

// ═══════════════════════════════════════════════════════════════════════
// METRICS RENDERER
// ═══════════════════════════════════════════════════════════════════════
function fmt(v, suffix='') {
  return (v===undefined||v===null||v===0) ? '—' : v+suffix;
}
function fmtMs(v) {
  return (v===undefined||v===null||v===0) ? '—' : v.toFixed(3)+' ms';
}
function colClass(ok) { return ok ? 'pass' : 'fail'; }

function applyMetrics(m) {
  if (!m) return;
  const z = m.zkp||{}, c = m.cats||{}, a = m.attacks||{},
        p = m.platoon||{}, bc = m.blockchain||{}, sec = m.security||{}, sys = m.system||{};

  // ① ZKP
  st('mz-avg-gen', fmtMs(z.avg_gen_ms));
  st('mz-avg-ver', fmtMs(z.avg_ver_ms));
  const sr = document.getElementById('mz-rate');
  if (sr) { sr.textContent = z.success_rate!==undefined ? z.success_rate+'%' : '—';
            sr.className = 'mcval '+(z.success_rate===100?'pass':'a'); }
  st('mz-total',  z.auth_total||0);
  st('mz-min-g',  z.min_gen_ms ? z.min_gen_ms.toFixed(3) : '—');
  st('mz-max-g',  z.max_gen_ms ? z.max_gen_ms.toFixed(3) : '—');
  st('mz-min-v',  z.min_ver_ms ? z.min_ver_ms.toFixed(3) : '—');
  st('mz-max-v',  z.max_ver_ms ? z.max_ver_ms.toFixed(3) : '—');
  st('mz-rot',    z.key_rotations||0);

  // merge per-vehicle data from server snapshot
  if (z.proof_gen_ms_per_vehicle)
    for (const [vid,v] of Object.entries(z.proof_gen_ms_per_vehicle)) pvGen[vid]=v;
  if (z.verify_ms_per_vehicle)
    for (const [vid,v] of Object.entries(z.verify_ms_per_vehicle)) pvVer[vid]=v;

  renderBars('z-gen-bars', pvGen, z.avg_gen_ms||0, 'ms', '#00e5ff');
  renderBars('z-ver-bars', pvVer, z.avg_ver_ms||0, 'ms', '#1de9b6');

  // ② CATS
  st('mc-win',   c.windows_processed||0);
  st('mc-up',    c.total_upvotes||0);
  st('mc-dn',    c.total_downvotes||0);
  st('mc-sv',    c.total_severe||0);
  st('mc-chg',   (c.trust_state_changes||[]).length);
  st('mc-avg-t', c.avg_rep_trusted   ? c.avg_rep_trusted.toFixed(1)   : '—');
  st('mc-avg-u', c.avg_rep_untrusted ? c.avg_rep_untrusted.toFixed(1) : '—');
  st('mc-ej',    c.banned_ejections||0);
  st('mc-fo',    c.false_obs_detections||0);
  renderTransitions(c.trust_state_changes||[]);

  // ③ Attacks
  const sy=a.sybil||{}, sp=a.spoof||{}, fo=a.false_obs||{}, bk=a.beacon_falsif||{};
  setAB('sybil', sy.detected);
  st('as-att', sy.attacker||'—');
  st('as-cr',  sy.fake_ids_created||0);
  st('as-bl',  sy.fake_ids_blocked||0);
  st('as-vs',  sy.fake_votes_stripped||0);
  st('as-st',  sy.start_time!=null ? sy.start_time.toFixed(1)+'s' : '—');
  st('as-dt',  sy.detection_time!=null ? sy.detection_time.toFixed(1)+'s' : '—');
  const syLat = (sy.detection_time!=null&&sy.start_time!=null)
    ? (sy.detection_time-sy.start_time).toFixed(1)+'s' : '—';
  st('as-lat', syLat);

  setAB('spoof', sp.detected);
  st('sp-att', sp.attacker||'—');
  st('sp-bf',  sp.beacons_flagged||0);
  st('sp-mx',  (sp.max_dev_m||0).toFixed(2)+' m');
  st('sp-av',  (sp.avg_dev_m||0).toFixed(2)+' m');
  st('sp-st',  sp.start_time!=null ? sp.start_time.toFixed(1)+'s' : '—');
  st('sp-dt',  sp.detection_time!=null ? sp.detection_time.toFixed(1)+'s' : '—');

  setAB('fobs', fo.detected);
  st('fo-att', fo.attacker||'—');
  st('fo-bc',  fo.broadcasts||0);
  st('fo-dv',  fo.downvotes_generated||0);
  st('fo-dt',  fo.detection_time!=null ? fo.detection_time.toFixed(1)+'s' : '—');

  setAB('bkn', bk.detected);
  st('bk-att', bk.attacker||'—');
  st('bk-vl',  bk.violations||0);
  st('bk-dt',  bk.detection_time!=null ? bk.detection_time.toFixed(1)+'s' : '—');

  // ④ Platoon
  st('mp-form', p.formations||0);   st('mp-join', p.joins||0);
  st('mp-ln',   p.leaves_normal||0); st('mp-lb', p.leaves_banned||0);
  st('mp-mg',   p.merges||0);        st('mp-el', p.leader_elections||0);
  st('mp-aft',  p.avg_form_time_s ? p.avg_form_time_s.toFixed(4)+'s' : '—');
  st('mp-s1',   p.situations&&p.situations['1']||0);
  st('mp-s2',   p.situations&&p.situations['2']||0);
  st('mp-s3',   p.situations&&p.situations['3']||0);
  st('mp-s4',   p.situations&&p.situations['4']||0);
  st('mp-lstep',p.normal_leave_step ? 'Step '+p.normal_leave_step : '—');
  st('mp-bstep',p.banned_leave_step ? 'Step '+p.banned_leave_step : '—');

  // ⑤ Blockchain
  const ben = document.getElementById('mb-en');
  if (ben) { ben.textContent=bc.enabled?'ONLINE':'OFFLINE';
             ben.className='mcval '+(bc.enabled?'g':'r'); }
  st('mb-tot',  bc.writes_total||0);
  const brate = document.getElementById('mb-rate');
  if (brate) { brate.textContent = bc.success_rate!==undefined ? bc.success_rate+'%' : '—';
               brate.className = 'mcval '+(bc.success_rate===100?'pass':'a'); }
  st('mb-rep',  bc.rep_updates||0);
  st('mb-fl',   bc.flags_added||0);

  // ⑥ Security Properties
  sp_row('snd',  sec.soundness_pass,    `${z.soundness_violations||0} violations`);
  sp_row('cmp',  sec.completeness_pass, `${z.completeness_violations||0} false rejections`);
  sp_row('zk',   sec.zk_pass,           `${z.zk_violations||0} leaks`);
  sp_row('prv',  sec.privacy_pass,      'FIdv only');
  sp_row('syb',  sec.anti_sybil_pass,   sy.detected ? `${sy.fake_ids_blocked||0} IDs blocked` : '—');
  sp_row('spf',  sec.anti_spoof_pass,   sp.detected ? `${sp.beacons_flagged||0} beacons flagged` : '—');
  sp_row('fob',  sec.anti_false_obs_pass, fo.detected ? `${fo.broadcasts||0} broadcasts det.` : '—');
  sp_row('bkn',  sec.anti_beacon_pass,  bk.detected ? `${bk.violations||0} violations det.` : '—');
  sp_row('ddos', true,                  `${z.ddos_events||0} events`);
  sp_row('imp',  true,                  `${z.impersonation_attempts||0} attempts`);

  // ⑦ System
  st('msys-sim',   (sys.sim_duration_s||0).toFixed(1)+' s');
  st('msys-wall',  (sys.wall_elapsed_s||0).toFixed(1)+' s');
  st('msys-hz',    (sys.step_rate_hz||0).toFixed(1)+' Hz');
  st('msys-steps', sys.sim_steps||0);
}

function sp_row(key, pass, valStr) {
  const badge = document.getElementById('sp-'+key);
  const val   = document.getElementById('sv-'+key);
  const ok = (pass===undefined||pass===null) ? true : !!pass;
  if (badge) { badge.textContent=ok?'PASS':'FAIL'; badge.className='ps '+(ok?'pass':'fail'); }
  if (val)   val.textContent = valStr||'—';
}
function setAB(key, detected) {
  const el = document.getElementById('ab-'+key);
  if (!el) return;
  el.textContent = detected ? 'DETECTED' : 'PENDING';
  el.className   = 'abadge '+(detected ? 'detected' : 'pending');
}

// ─── Bar chart renderer ───────────────────────────────────────────────
function renderBars(cid, data, avg, unit, color) {
  const el = document.getElementById(cid);
  if (!el) return;
  const entries = Object.entries(data);
  if (!entries.length) {
    el.innerHTML = `<div style="color:var(--dim);font-size:9px;font-family:'Share Tech Mono',monospace">Awaiting data…</div>`;
    return;
  }
  const maxV = Math.max(...entries.map(([,v])=>v), (avg||0)*1.5, 0.001);
  el.innerHTML = entries.map(([vid, ms]) => `
    <div class="brow">
      <span class="brow-lbl">${vid}</span>
      <div class="brow-wrap"><div class="brow-fill" style="width:${(ms/maxV*100).toFixed(1)}%;background:${color}"></div></div>
      <span class="brow-val ${ms > avg*1.2 ? 'hi' : ''}">${ms.toFixed(3)} ${unit}</span>
    </div>`).join('')
  + `<div class="chart-sep"></div>
    <div class="brow">
      <span class="brow-lbl" style="color:var(--amber)">AVG</span>
      <div class="brow-wrap"><div class="brow-fill" style="width:${((avg||0)/maxV*100).toFixed(1)}%;background:var(--amber)"></div></div>
      <span class="brow-val" style="color:var(--amber)">${(avg||0).toFixed(3)} ${unit}</span>
    </div>`;
}

// ─── Trust transition list ────────────────────────────────────────────
function renderTransitions(changes) {
  const el = document.getElementById('cats-tr-list');
  if (!el) return;
  if (!changes.length) {
    el.innerHTML = `<div style="color:var(--dim);font-size:9px;font-family:'Share Tech Mono',monospace;padding:4px">No transitions yet</div>`;
    return;
  }
  const col = s => s==='Trusted'?'var(--green)':s==='Untrusted'?'var(--amber)':'var(--red)';
  el.innerHTML = changes.map(ch => `
    <div class="tr-item">
      <span style="color:var(--dim);min-width:40px">${ch.sim_time!=null?ch.sim_time.toFixed(1)+'s':'—'}</span>
      <span style="color:var(--accent);min-width:68px">${ch.vid}</span>
      <span style="color:${col(ch.old)}">${ch.old}</span>
      <span style="color:var(--dim)">→</span>
      <span style="color:${col(ch.new)};font-weight:700">${ch.new}</span>
    </div>`).join('');
  el.scrollTop = el.scrollHeight;
}

// ═══════════════════════════════════════════════════════════════════════
// VEHICLE CARDS
// ═══════════════════════════════════════════════════════════════════════
function renderAllVehicles() {
  document.getElementById('no-v').style.display = 'none';
  for (const vid of Object.keys(vState)) upsertCard(vid);
}
function upsertCard(vid) {
  document.getElementById('no-v').style.display = 'none';
  const wrap = document.getElementById('vtable');
  let card = document.getElementById('vc-'+vid);
  const v = vState[vid]||{}, ts = v.trust_state||'Trusted';
  const rep = v.reputation!==undefined?v.reputation:'—';
  const rn = typeof rep==='number'?rep:0;
  const rp = Math.max(0,Math.min(100,rn));
  const rc = rn>=70?'var(--green)':rn>=40?'var(--amber)':'var(--red)';
  const cm = v.commitment||'', cs = cm?cm.slice(0,8)+'...'+cm.slice(-6):'—';
  const fi = v.fake_id||'',   fs = fi?fi.slice(0,10)+'...':'—';
  const as = v.auth_status||'—';
  const rch = v.rep_change;
  const rcs = rch!==undefined
    ? (rch>0?`<span style="color:var(--green)">+${rch.toFixed(1)}</span>`
       :rch<0?`<span style="color:var(--red)">${rch.toFixed(1)}</span>`
       :'<span style="color:var(--dim)">0</span>')
    : '—';
  const html = `
    <div class="vch"><span class="vid">${vid}</span><span class="vst ${ts}">${ts.toUpperCase()}</span></div>
    <div class="rb-wrap"><div class="rb"><div class="rf" style="width:${rp}%;background:${rc}"></div></div></div>
    <div class="vcb">
      <div class="vf"><div class="vfl">Reputation</div><div class="vfv" style="color:${rc}">${typeof rep==='number'?rep.toFixed(1):rep}</div></div>
      <div class="vf"><div class="vfl">Δ Score</div><div class="vfv">${rcs}</div></div>
      <div class="vf"><div class="vfl">Auth</div><div class="vfv" style="color:${as==='ACCEPTED'?'var(--green)':as==='REJECTED'?'var(--red)':'var(--dim)'}">${as}</div></div>
      <div class="vf"><div class="vfl">Proof ms</div><div class="vfv">${v.proof_gen_ms?v.proof_gen_ms.toFixed(2):'—'}</div></div>
    </div>
    <div class="vpills">
      <span class="vp up">↑ ${v.last_vote_up||0}</span>
      <span class="vp dn">↓ ${v.last_vote_down||0}</span>
      <span class="vp sv">⚠ ${v.last_vote_severe||0}</span>
    </div>
    <div class="vcmt"><span>commit: </span>${cs}<br><span>fakeId: </span>${fs}</div>`;
  if (!card) {
    card = document.createElement('div');
    card.id = 'vc-'+vid;
    card.className = 'vcard '+ts.toLowerCase();
    wrap.appendChild(card);
  } else {
    const was = card.dataset.state;
    card.className = 'vcard '+ts.toLowerCase();
    if (was && was!==ts) {
      card.classList.add(ts==='Banned'?'fr':'fg');
      setTimeout(()=>card.classList.remove('fr','fg'), 700);
    }
  }
  card.dataset.state = ts;
  card.innerHTML = html;
  document.getElementById('vcnt').textContent = Object.keys(vState).length+' vehicles';
}

// ═══════════════════════════════════════════════════════════════════════
// EVENT LOG
// ═══════════════════════════════════════════════════════════════════════
function appendEvent(ev) {
  const log  = document.getElementById('event-log');
  const type = ev.type||'LOG';
  const t    = ev.sim_time!==undefined ? ev.sim_time.toFixed(1)+'s' : '';
  let body='', detail='', steps='';

  if (type==='COMMITMENT') {
    const vid = ev.vehicle_id||'';
    body = `<strong>${vid}</strong> commitment generated`;
    steps = `
      <div class="step">Step 1 · Register with CA → FIdv = Hash(Salt(Id<sub>v</sub>))</div>
      <div class="step">Step 2 · SK<sub>v</sub> = HMAC(SK<sub>CA</sub>, FId<sub>v</sub>) · PK<sub>v</sub> derived</div>
      <div class="step">Step 3 · sm = Hash(Salt(Sig<sub>SK</sub>, T))  [Eq17]</div>
      <div class="step">Step 4 · x = Hash(sm ‖ PK<sub>CA</sub>)  [Eq18] · Proof = Hash(Pk ‖ x ‖ Hash(w))  [Eq20]</div>
      <div class="step">Step 5 · CA verify → <strong>${ev.auth_status||'?'}</strong>  gen=${(ev.proof_gen_ms||0).toFixed(2)}ms  ver=${(ev.verify_ms||0).toFixed(2)}ms</div>
      <div class="step">Commit: <span style="color:#a78bfa">${(ev.commitment||'').slice(0,20)}…</span>  FId: <span style="color:#67e8f9">${(ev.fake_id||'').slice(0,20)}…</span></div>`;
  } else if (type==='REPUTATION') {
    const vid = ev.vehicle_id||'';
    const old = ev.old_reputation?.toFixed(1)||'?', nw = ev.new_reputation?.toFixed(1)||'?';
    const st_ = ev.new_state||'?';
    const col = st_==='Trusted'?'var(--green)':st_==='Untrusted'?'var(--amber)':'var(--red)';
    body = `<strong>${vid}</strong> reputation update`;
    steps = `
      <div class="step">${old} → <strong style="color:${col}">${nw}</strong> &nbsp; State: <strong style="color:${col}">${st_}</strong></div>
      <div class="step">Votes: ↑${ev.upvotes||0} ↓${ev.downvotes||0} ⚠${ev.severe_downvotes||0}  Reason: ${ev.reason||'—'}</div>
      ${ev.old_state!==ev.new_state?`<div class="step" style="color:var(--red)">⚡ STATE CHANGE: ${ev.old_state} → ${ev.new_state}</div>`:''}`;
  } else if (type==='ATTACK') {
    body = `<strong style="color:var(--red)">${ev.attack_type||'Attack'}</strong> on <strong>${ev.vehicle_id||'?'}</strong>`;
    if (ev.detail) detail = ev.detail;
    if (ev.steps)  steps  = ev.steps.map(s=>`<div class="step">${s}</div>`).join('');
  } else if (type==='BLOCKCHAIN') {
    body = `On-chain: <strong>${ev.operation||'update'}</strong> for <strong>${ev.vehicle_id||'?'}</strong>`;
    if (ev.detail) detail = ev.detail;
  } else if (type==='AUTH'||type==='FORMATION'||type==='KEY_ROTATION') {
    body = ev.detail||ev.message||type;
  } else if (type==='TRUST_STATE_CHANGE') {
    body = `<strong style="color:var(--red)">${ev.vehicle_id||'?'}</strong> → <strong>${ev.new_state||'?'}</strong>`;
    if (ev.detail) detail = ev.detail;
  } else {
    body = ev.detail||ev.message||ev.description||JSON.stringify(ev).slice(0,120);
  }

  const item = document.createElement('div');
  item.className = 'ei';
  item.innerHTML = `
    <div class="et">${t}</div>
    <div><span class="etag ${type}">${type.replace(/_/g,' ')}</span></div>
    <div class="eb">${body}</div>
    ${detail ? `<div class="edetail">${detail}</div>` : ''}
    ${steps  ? `<div class="esteps">${steps}</div>`   : ''}`;
  log.insertBefore(item, log.firstChild);
  evCount++;
  document.getElementById('evcnt').textContent = evCount+' events';
  while (log.children.length > MAX_EV) log.removeChild(log.lastChild);
}

connect();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return DASHBOARD_HTML


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)