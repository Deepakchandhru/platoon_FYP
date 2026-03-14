import proto.platoon_pb2 as platoon_pb2
import uuid

def member_row_to_pb(row):
    m = platoon_pb2.PlatoonMember(
        plate_number=row["plate_number"],
        is_leader=row["is_leader"],
        position=int(row["position"])
    )
    return m

def platoon_snapshot_pb(pid, members, speed=0.0):
    p = platoon_pb2.Platoon(pid=pid, speed=speed)
    for r in members:
        p.members.append(member_row_to_pb(r))
    return p

async def join_platoon(request, context, db_pool, persist_event_and_broadcast):
    plate = (request.plate_number or "").strip()
    pid = (request.pid or "").strip()
    if not plate:
        return platoon_pb2.JoinResponse(ok=False, pid="", message="empty plate_number")

    async with db_pool.acquire() as conn:
        reg = await conn.fetchrow("SELECT plate_number FROM registered WHERE plate_number=$1", plate)
        if not reg:
            return platoon_pb2.JoinResponse(ok=False, pid="", message="vehicle not registered")

        current = await conn.fetchrow("SELECT pid FROM platoon_members WHERE plate_number=$1", plate)
        if current:
            return platoon_pb2.JoinResponse(ok=False, pid=current["pid"], message=f"Already in platoon {current['pid']} - leave first.")

        async with conn.transaction():
            if not pid:
                pid = "p-" + uuid.uuid4().hex[:12]
                await conn.execute("INSERT INTO platoons(pid, speed) VALUES($1,$2)", pid, 0.0)
                await conn.execute(
                    "INSERT INTO platoon_members(pid,plate_number,is_leader,position) VALUES($1,$2,$3,$4)",
                    pid, plate, True, 0
                )
                await conn.execute(
                    "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3) "
                    "ON CONFLICT (pid, plate_number) DO UPDATE SET speed=EXCLUDED.speed",
                    pid, plate, 0.0
                )
                members = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", pid)
                pb = platoon_snapshot_pb(pid, members, 0.0)
                await persist_event_and_broadcast(
                    conn, "PLATOON_JOINED", "CAR", plate, pid, "PLATOON", pid, "created and joined",
                    {"position": 0}, pb
                )
                return platoon_pb2.JoinResponse(ok=True, pid=pid, message="created and joined")

            exists = await conn.fetchrow("SELECT pid, speed FROM platoons WHERE pid=$1", pid)
            if not exists:
                return platoon_pb2.JoinResponse(ok=False, pid="", message="platoon does not exist")

            platoon_speed = exists["speed"] or 0.0
            tail_pos = await conn.fetchval("SELECT COALESCE(MAX(position),-1) FROM platoon_members WHERE pid=$1", pid)

            await conn.execute(
                "INSERT INTO platoon_members(pid,plate_number,is_leader,position) VALUES($1,$2,$3,$4)",
                pid, plate, False, int(tail_pos) + 1
            )
            await conn.execute(
                "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3) "
                "ON CONFLICT (pid, plate_number) DO UPDATE SET speed=EXCLUDED.speed",
                pid, plate, platoon_speed
            )
            await conn.execute(
                "UPDATE platoons SET speed=$1 WHERE pid=$2",
                platoon_speed, pid
            )
            members = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", pid)
            pb = platoon_snapshot_pb(pid, members, platoon_speed)
            await persist_event_and_broadcast(
                conn, "PLATOON_JOINED", "CAR", plate, pid, "PLATOON", pid, "joined",
                {"position": int(tail_pos) + 1}, pb
            )
            return platoon_pb2.JoinResponse(ok=True, pid=pid, message="joined")

async def leave_platoon(request, context, db_pool, persist_event_and_broadcast):
    plate = (request.plate_number or "").strip()
    if not plate:
        return platoon_pb2.LeaveResponse(ok=False, message="empty plate_number")

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            me = await conn.fetchrow("SELECT * FROM platoon_members WHERE plate_number=$1", plate)
            if not me:
                return platoon_pb2.LeaveResponse(ok=False, message="vehicle not in any platoon")

            pid = me["pid"]
            my_pos = int(me["position"])
            tail_pos = int(await conn.fetchval("SELECT COALESCE(MAX(position),0) FROM platoon_members WHERE pid=$1", pid))

            if my_pos == tail_pos:
                await conn.execute("DELETE FROM platoon_members WHERE id=$1", me["id"])
                await conn.execute("DELETE FROM platoon_speeds WHERE pid=$1 AND plate_number=$2", pid, plate)

                remain = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", pid)
                if remain and not any(r["is_leader"] for r in remain):
                    await conn.execute("UPDATE platoon_members SET is_leader=TRUE WHERE pid=$1 AND position=0", pid)
                elif not remain:
                    await conn.execute("DELETE FROM platoons WHERE pid=$1", pid)
                    await conn.execute("DELETE FROM platoon_speeds WHERE pid=$1", pid)

                pb = platoon_snapshot_pb(pid, remain, float(await conn.fetchval("SELECT COALESCE(speed,0.0) FROM platoons WHERE pid=$1", pid) or 0.0)) if remain else None
                await persist_event_and_broadcast(conn, "PLATOON_LEFT", "CAR", plate, pid, "PLATOON", pid, "left (tail)", None, pb)
                return platoon_pb2.LeaveResponse(ok=True, message="left (tail)" if remain else "left and platoon dissolved")

            temp_pid = "p-" + uuid.uuid4().hex[:12]
            await conn.execute("INSERT INTO platoons(pid) VALUES($1)", temp_pid)

            tail_rows = await conn.fetch("SELECT plate_number FROM platoon_members WHERE pid=$1 AND position>$2 ORDER BY position ASC", pid, my_pos)
            src_speed = float(await conn.fetchval("SELECT COALESCE(speed,0.0) FROM platoons WHERE pid=$1", pid) or 0.0)

            for idx, r in enumerate(tail_rows):
                await conn.execute("DELETE FROM platoon_members WHERE pid=$1 AND plate_number=$2", pid, r["plate_number"])
                await conn.execute(
                    "INSERT INTO platoon_members(pid, plate_number, is_leader, position) VALUES($1,$2,$3,$4)",
                    temp_pid, r["plate_number"], False, idx
                )
                await conn.execute(
                    "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3)",
                    temp_pid, r["plate_number"], src_speed
                )
                await conn.execute("DELETE FROM platoon_speeds WHERE pid=$1 AND plate_number=$2", pid, r["plate_number"])

            await conn.execute("DELETE FROM platoon_members WHERE id=$1", me["id"])
            await conn.execute("DELETE FROM platoon_speeds WHERE pid=$1 AND plate_number=$2", pid, plate)
            await conn.execute("UPDATE platoon_members SET position = position - 1 WHERE pid=$1 AND position>$2", pid, my_pos)

            head_members = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", pid)
            if head_members and not any(r["is_leader"] for r in head_members):
                await conn.execute("UPDATE platoon_members SET is_leader=TRUE WHERE pid=$1 AND position=0", pid)

            tail_members = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", temp_pid)
            if tail_members and not any(r["is_leader"] for r in tail_members):
                await conn.execute("UPDATE platoon_members SET is_leader=TRUE WHERE pid=$1 AND position=0", temp_pid)

            base_pos = int(await conn.fetchval("SELECT COALESCE(MAX(position),-1) FROM platoon_members WHERE pid=$1", pid)) + 1
            for i, r in enumerate(tail_members):
                await conn.execute(
                    "INSERT INTO platoon_members(pid, plate_number, is_leader, position) VALUES($1,$2,$3,$4)",
                    pid, r["plate_number"], False, base_pos + i
                )
                await conn.execute(
                    "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3)",
                    pid, r["plate_number"], src_speed
                )
            await conn.execute("DELETE FROM platoons WHERE pid=$1", temp_pid)
            await conn.execute("DELETE FROM platoon_speeds WHERE pid=$1", temp_pid)

            final_members = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", pid)
            pb_final = platoon_snapshot_pb(pid, final_members, src_speed)
            await persist_event_and_broadcast(conn, "PLATOON_LEFT", "CAR", plate, pid, "PLATOON", pid, "left (split->merge)", {"leave_pos": my_pos}, pb_final)

            return platoon_pb2.LeaveResponse(ok=True, message="left (split->merge)")

async def merge_platoon(request, context, db_pool, persist_event_and_broadcast):
    plate = (request.plate_number or "").strip()
    src = (request.src_pid or "").strip()
    dst = (request.dst_pid or "").strip()

    if not plate or not src or not dst or src == dst:
        return platoon_pb2.MergeResponse(ok=False, dst_pid="", message="invalid src/dst")

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            src_platoon = await conn.fetchrow("SELECT pid FROM platoons WHERE pid=$1", src)
            dst_platoon = await conn.fetchrow("SELECT pid FROM platoons WHERE pid=$1", dst)
            if not src_platoon or not dst_platoon:
                return platoon_pb2.MergeResponse(ok=False, dst_pid="", message="source or dest not found")

            leader_check = await conn.fetchrow(
                "SELECT is_leader FROM platoon_members WHERE pid=$1 AND plate_number=$2",
                src, plate
            )
            if not leader_check or not leader_check["is_leader"]:
                return platoon_pb2.MergeResponse(ok=False, dst_pid="", message="only source platoon leader can request merge")

            base_pos = int(await conn.fetchval("SELECT COALESCE(MAX(position),-1) FROM platoon_members WHERE pid=$1", dst)) + 1

            src_members = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", src)

            dst_leader_plate = await conn.fetchval(
                "SELECT plate_number FROM platoon_members WHERE pid=$1 AND is_leader=TRUE", dst
            )
            dst_leader_speed = await conn.fetchval(
                "SELECT speed FROM platoon_speeds WHERE pid=$1 AND plate_number=$2", dst, dst_leader_plate
            ) or 0.0

            for i, m in enumerate(src_members):
                await conn.execute(
                    "INSERT INTO platoon_members(pid, plate_number, is_leader, position) VALUES($1,$2,$3,$4)",
                    dst, m["plate_number"], False, base_pos + i
                )
                await conn.execute(
                    "INSERT INTO platoon_speeds(pid, plate_number, speed) VALUES($1,$2,$3)",
                    dst, m["plate_number"], dst_leader_speed
                )

            await conn.execute("DELETE FROM platoons WHERE pid=$1", src)
            await conn.execute("DELETE FROM platoon_speeds WHERE pid=$1", src)

            final_members = await conn.fetch("SELECT * FROM platoon_members WHERE pid=$1 ORDER BY position ASC", dst)
            pb_final = platoon_snapshot_pb(dst, final_members, dst_leader_speed)
            await persist_event_and_broadcast(
                conn, "PLATOON_MERGED", "PLATOON", dst, dst, "PLATOON", src,
                f"merged {src} -> {dst}", None, pb_final
            )

            return platoon_pb2.MergeResponse(ok=True, dst_pid=dst, message="merged")