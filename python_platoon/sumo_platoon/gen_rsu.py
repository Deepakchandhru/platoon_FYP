import xml.etree.ElementTree as ET
import math
import argparse
from typing import List, Tuple

def parse_shape(shape_str: str) -> List[Tuple[float,float]]:
    pts = []
    for p in shape_str.strip().split():
        if not p:
            continue
        x,y = p.split(",")
        pts.append((float(x), float(y)))
    return pts

def seg_lengths(points: List[Tuple[float,float]]) -> List[float]:
    L = []
    for i in range(1, len(points)):
        dx = points[i][0] - points[i-1][0]
        dy = points[i][1] - points[i-1][1]
        L.append(math.hypot(dx,dy))
    return L

def interp_along_poly(points: List[Tuple[float,float]], dist: float) -> Tuple[float,float,int,float]:
    # returns (x,y, segment_index, t) where t in [0,1] along segment
    if dist <= 0:
        return points[0][0], points[0][1], 0, 0.0
    lens = seg_lengths(points)
    cum = 0.0
    for i, l in enumerate(lens):
        if cum + l >= dist:
            t = (dist - cum) / (l if l>0 else 1.0)
            x = points[i][0] + (points[i+1][0] - points[i][0]) * t
            y = points[i][1] + (points[i+1][1] - points[i][1]) * t
            return x, y, i, t
        cum += l
    # beyond end -> return last point
    return points[-1][0], points[-1][1], len(points)-2, 1.0

def unit_perp_between(p0: Tuple[float,float], p1: Tuple[float,float]) -> Tuple[float,float]:
    dx = p1[0] - p0[0]; dy = p1[1] - p0[1]
    n = math.hypot(dx,dy) or 1.0
    ux = -dy / n; uy = dx / n
    return ux, uy

def generate_pois_from_net(net_path: str, out_path: str, spacing: float = 500.0, lateral_offset: float = 6.0, lanes_to_use: int = None):
    tree = ET.parse(net_path)
    root = tree.getroot()
    pois = []
    idx = 0
    # iterate lanes inside edges (prefer lane shape if available)
    for edge in root.findall(".//edge"):
        edge_id = edge.get("id")
        if not edge_id or edge_id.startswith(":"):
            continue
        # prefer first lane child shape; if none, use edge@shape
        lane_elems = edge.findall("lane")
        lane_shapes = []
        if lane_elems:
            for ln in lane_elems:
                s = ln.get("shape")
                if s:
                    lane_shapes.append(s)
        else:
            s = edge.get("shape")
            if s:
                lane_shapes.append(s)
        if not lane_shapes:
            continue
        # process first lane shape (you can change to all lanes)
        for shape_str in lane_shapes[:1]:
            pts = parse_shape(shape_str)
            if len(pts) < 2:
                continue
            # compute total length
            segs = seg_lengths(pts)
            total = sum(segs)
            # sample every spacing meters
            pos = spacing
            while pos < total:
                x, y, si, t = interp_along_poly(pts, pos)
                # compute perpendicular vector for that segment
                # pick the segment endpoints
                p0 = pts[si]; p1 = pts[si+1]
                ux, uy = unit_perp_between(p0, p1)
                # left and right points (two RSU markers)
                left_x = x + ux * lateral_offset
                left_y = y + uy * lateral_offset
                right_x = x - ux * lateral_offset
                right_y = y - uy * lateral_offset
                pois.append(("rsu_%06d_L" % idx, left_x, left_y))
                idx += 1
                pois.append(("rsu_%06d_R" % idx, right_x, right_y))
                idx += 1
                pos += spacing
    # write additional file
    add_root = ET.Element("additional")
    for pid, x, y in pois:
        poi = ET.SubElement(add_root, "poi")
        poi.set("id", pid)
        poi.set("x", f"{x:.3f}")
        poi.set("y", f"{y:.3f}")
        poi.set("z", "0.0")
        poi.set("radius", "1.0")
        poi.set("color", "0,200,40")
        poi.set("text", "RSU")
    tree = ET.ElementTree(add_root)
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
    print(f"Wrote {len(pois)} POIs to {out_path}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Generate RSU POIs from SUMO net file")
    p.add_argument("--net", "-n", required=True, help="path to guindy.net.xml (SUMO net)")
    p.add_argument("--out", "-o", default="rsu.add.xml", help="output additional file")
    p.add_argument("--spacing", "-s", type=float, default=500.0, help="distance between RSUs (m)")
    p.add_argument("--offset", "-f", type=float, default=6.0, help="lateral offset from lane center (m)")
    args = p.parse_args()
    generate_pois_from_net(args.net, args.out, spacing=args.spacing, lateral_offset=args.offset)