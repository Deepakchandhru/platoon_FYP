import proto.platoon_pb2 as platoon_pb2
import math
from typing import Optional

async def report_speed(request, context, db_pool, platoon_snapshot_pb, persist_event_and_broadcast):
    pid = (request.pid or "").strip()
    plate = (request.plate_number or "").strip()
    try:
        speed = float(request.speed)
    except Exception:
        return platoon_pb2.SpeedAck(ok=False, message="invalid speed")
    if not pid or not plate:
        return platoon_pb2.SpeedAck(ok=False, message="missing pid or plate_number")
    async with db_pool.acquire() as conn:
        leader_check = await conn.fetchrow("SELECT is_leader FROM platoon_members WHERE pid=$1 AND plate_number=$2", pid, plate)
        if not leader_check:
            return platoon_pb2.SpeedAck(ok=False, message="not in platoon")
        if not leader_check["is_leader"]:
            return platoon_pb2.SpeedAck(ok=False, message="not leader")
        await conn.execute("UPDATE platoons SET speed=$1 WHERE pid=$2", speed, pid)
        members = await conn.fetch("SELECT plate_number FROM platoon_members WHERE pid=$1 ORDER BY position ASC", pid)
        for m in members:
            await conn.execute(
                "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1, $2, $3) "
                "ON CONFLICT (pid, plate_number) DO UPDATE SET speed=EXCLUDED.speed",
                pid, m["plate_number"], speed
            )
        members_rows = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", pid)
        pb = platoon_snapshot_pb(pid, members_rows, speed)
        await persist_event_and_broadcast(conn, "SPEED_UPDATE", "CAR", plate, pid, "PLATOON", pid, f"leader speed={speed}", {"speed": speed}, pb)
        return platoon_pb2.SpeedAck(ok=True, message="leader speed applied to platoon")

async def get_platoon_speeds(request, context, db_pool, now_timestamp):
    pid = (request.pid or "").strip()
    resp = platoon_pb2.PlatoonSpeeds(pid=pid)
    if not pid:
        return resp
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT plate_number, speed, updated FROM platoon_speeds WHERE pid=$1", pid)
        for r in rows:
            su = platoon_pb2.SpeedUpdate(pid=pid, plate_number=r["plate_number"], speed=r["speed"])
            su.ts.CopyFrom(now_timestamp())
            resp.speeds.append(su)
    return resp

async def lane_change(request, context, db_pool, persist_event_and_broadcast):
    pid = (request.pid or "").strip()
    plate = (request.plate_number or "").strip()
    lane_raw = (request.lane or "").strip()
    if not pid or not plate or lane_raw == "":
        return platoon_pb2.LaneChangeAck(ok=False, message="missing pid, plate_number, or lane")

    # validate lane value (expect numeric or short label)
    lane_val = lane_raw
    try:
        # prefer numeric lane index where possible
        lane_idx = int(lane_raw)
        lane_val = str(lane_idx)
    except Exception:
        # keep textual lane identifiers (e.g. "left", "right") if provided
        lane_val = lane_raw

    async with db_pool.acquire() as conn:
        member = await conn.fetchrow("SELECT * FROM platoon_members WHERE pid=$1 AND plate_number=$2", pid, plate)
        if not member:
            return platoon_pb2.LaneChangeAck(ok=False, message="not in platoon")

        # realistic: mark desired lane and publish event; controller/clients perform smooth change
        await conn.execute("UPDATE platoon_members SET lane=$1 WHERE pid=$2 AND plate_number=$3", lane_val, pid, plate)
        await persist_event_and_broadcast(conn, "LANE_CHANGE", "CAR", plate, pid, "PLATOON", pid, f"lane change to {lane_val}", {"lane": lane_val})
        return platoon_pb2.LaneChangeAck(ok=True, message=f"lane change requested to {lane_val}")

async def take_turning(request, context, db_pool, persist_event_and_broadcast):
    pid = (request.pid or "").strip()
    plate = (request.plate_number or "").strip()
    direction = (request.direction or "").strip().lower()
    if not pid or not plate or direction not in ("left", "right"):
        return platoon_pb2.TurningAck(ok=False, message="missing pid, plate_number, or invalid direction")
    async with db_pool.acquire() as conn:
        member = await conn.fetchrow("SELECT * FROM platoon_members WHERE pid=$1 AND plate_number=$2", pid, plate)
        if not member:
            return platoon_pb2.TurningAck(ok=False, message="not in platoon")
        await persist_event_and_broadcast(conn, "TURNING", "CAR", plate, pid, "PLATOON", pid, f"taking {direction} turn", {"direction": direction})
        return platoon_pb2.TurningAck(ok=True, message=f"taking {direction} turn")

async def apply_brake(request, context, db_pool, persist_event_and_broadcast):
    pid = (request.pid or "").strip()
    plate = (request.plate_number or "").strip()
    intensity = request.intensity
    if not pid or not plate or not (0.0 <= intensity <= 1.0):
        return platoon_pb2.BrakeAck(ok=False, message="missing pid, plate_number, or invalid intensity")

    async with db_pool.acquire() as conn:
        member = await conn.fetchrow("SELECT * FROM platoon_members WHERE pid=$1 AND plate_number=$2", pid, plate)
        if not member:
            return platoon_pb2.BrakeAck(ok=False, message="not in platoon")

        # determine current reference speed for this platelet (prefer per-vehicle speed then platoon speed)
        row_speed = await conn.fetchrow("SELECT speed FROM platoon_speeds WHERE pid=$1 AND plate_number=$2", pid, plate)
        if row_speed and row_speed["speed"] is not None:
            cur_speed = float(row_speed["speed"])
        else:
            cur_speed = float(await conn.fetchval("SELECT COALESCE(speed,0.0) FROM platoons WHERE pid=$1", pid) or 0.0)

        # simple braking model: new_speed = cur_speed * (1 - intensity)
        new_speed = max(0.0, cur_speed * (1.0 - float(intensity)))

        # update this vehicle's recorded speed
        await conn.execute(
            "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3) "
            "ON CONFLICT (pid, plate_number) DO UPDATE SET speed=EXCLUDED.speed",
            pid, plate, new_speed
        )

        # propagate to immediate follower (make follower adopt same speed)
        my_pos = int(member["position"])
        follower = await conn.fetchrow(
            "SELECT plate_number FROM platoon_members WHERE pid=$1 AND position=$2", pid, my_pos + 1
        )
        if follower:
            fol_plate = follower["plate_number"]
            await conn.execute(
                "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3) "
                "ON CONFLICT (pid, plate_number) DO UPDATE SET speed=EXCLUDED.speed",
                pid, fol_plate, new_speed
            )
            # notify follower specifically (event)
            await persist_event_and_broadcast(conn, "BRAKE", "CAR", plate, pid, "CAR", fol_plate,
                                             f"{plate} braked -> follower {fol_plate} set to {new_speed:.2f}",
                                             {"intensity": intensity, "new_speed": new_speed})
        else:
            # no follower: broadcast brake event to platoon
            await persist_event_and_broadcast(conn, "BRAKE", "CAR", plate, pid, "PLATOON", pid,
                                             f"{plate} braked -> new_speed={new_speed:.2f}", {"intensity": intensity, "new_speed": new_speed})

        # if the braking vehicle is leader, also update platoon nominal speed
        if member["is_leader"]:
            await conn.execute("UPDATE platoons SET speed=$1 WHERE pid=$2", new_speed, pid)

        return platoon_pb2.BrakeAck(ok=True, message=f"brake applied, new_speed={new_speed:.2f}")

async def overtake(request, context, db_pool, persist_event_and_broadcast):
    pid = (request.pid or "").strip()
    plate = (request.plate_number or "").strip()
    target_plate = (request.target_plate or "").strip()
    if not pid or not plate or not target_plate:
        return platoon_pb2.OvertakeAck(ok=False, message="missing pid, plate_number, or target_plate")

    async with db_pool.acquire() as conn:
        me = await conn.fetchrow("SELECT position FROM platoon_members WHERE pid=$1 AND plate_number=$2", pid, plate)
        target = await conn.fetchrow("SELECT position FROM platoon_members WHERE pid=$1 AND plate_number=$2", pid, target_plate)
        if not me or not target:
            return platoon_pb2.OvertakeAck(ok=False, message="member or target not in platoon")

        my_pos = int(me["position"])
        tgt_pos = int(target["position"])

        # allow overtaking only between immediate neighbours and only if overtaker is directly behind target
        # (larger position value means further from leader)
        if my_pos <= tgt_pos:
            return platoon_pb2.OvertakeAck(ok=False, message="overtaker must be behind target to overtake")
        print(f"Overtaking: my_pos={my_pos}, tgt_pos={tgt_pos}, plate={plate}, target_plate={target_plate}")
        if (my_pos - tgt_pos) != 1:
            return platoon_pb2.OvertakeAck(ok=False, message="overtake allowed only between neighboring vehicles")

        # perform position swap: target moves back one slot, overtaker moves into target's slot
        async with conn.transaction():
            # swap positions
            await conn.execute("UPDATE platoon_members SET position = -1 WHERE pid=$1 AND plate_number=$2", pid, plate)
            await conn.execute("UPDATE platoon_members SET position = $1 WHERE pid=$2 AND plate_number=$3", my_pos, pid, target_plate)
            await conn.execute("UPDATE platoon_members SET position = $1 WHERE pid=$2 AND plate_number=$3", tgt_pos, pid, plate)

            # normalize any -1 if present (should not remain)
            await conn.execute("UPDATE platoon_members SET position = position WHERE pid=$1", pid)

        # adjust speeds: overtaker may adopt slightly higher speed for maneuver (best-effort)
        target_speed_row = await conn.fetchrow("SELECT speed FROM platoon_speeds WHERE pid=$1 AND plate_number=$2", pid, target_plate)
        base_speed = float(target_speed_row["speed"]) if target_speed_row and target_speed_row["speed"] is not None else float(await conn.fetchval("SELECT COALESCE(speed,0.0) FROM platoons WHERE pid=$1", pid) or 0.0)
        overtaker_speed = min(base_speed + 2.0, 60.0)  # small boost for overtaking

        await conn.execute(
            "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3) "
            "ON CONFLICT (pid, plate_number) DO UPDATE SET speed=EXCLUDED.speed",
            pid, plate, overtaker_speed
        )
        # target slows slightly to indicate being overtaken
        await conn.execute(
            "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3) "
            "ON CONFLICT (pid, plate_number) DO UPDATE SET speed=EXCLUDED.speed",
            pid, target_plate, max(0.0, base_speed - 1.0)
        )

        await persist_event_and_broadcast(conn, "OVERTAKE", "CAR", plate, pid, "CAR", target_plate,
                                         f"{plate} overtook {target_plate}", {"overtaker_speed": overtaker_speed, "target_speed": base_speed - 1.0})
        return platoon_pb2.OvertakeAck(ok=True, message=f"overtook {target_plate}")