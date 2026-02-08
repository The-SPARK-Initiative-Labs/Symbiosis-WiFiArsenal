#!/usr/bin/env python3
"""
Wardrive Offline Tile Downloader

Downloads Google Maps tiles for offline wardriving.
- Zoom 1-18: Full coverage area (database bounds + large buffer)
- Zoom 19-20: Only near actual wardrive data points (500m buffer)
- Downloads BOTH satellite and street tiles

Just run it:  python3 download_tiles.py
Ctrl+C to stop - progress is saved, rerun to continue where you left off.
"""

import os
import sys
import sqlite3
import requests
import math
import time
import signal
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ============================================================
# CONFIGURATION - Edit these if needed
# ============================================================
DB_PATH = 'wardrive_data.db'
TILE_BASE = 'tiles'                # base directory
TILE_TYPES = {
    'y': 'satellite',              # satellite + labels (hybrid)
    'm': 'street',                 # street map
}
FULL_ZOOM = range(1, 19)           # 1-18: full area coverage
DETAIL_ZOOM = range(19, 21)        # 19-20: data points only
AREA_BUFFER = 0.5                  # degrees buffer for full area (~35 miles)
DETAIL_BUFFER_M = 500              # meters buffer around data points for 19-20
MAX_WORKERS = 30
MT_SERVERS = ['mt0', 'mt1', 'mt2', 'mt3']
# ============================================================

stats = {'downloaded': 0, 'skipped': 0, 'failed': 0, 'total_bytes': 0, 'start_time': 0}
stats_lock = Lock()
shutdown_flag = False
server_idx = 0
server_lock = Lock()
current_tile_type = 'y'

def signal_handler(sig, frame):
    global shutdown_flag
    print("\n\n  Download interrupted - progress saved. Rerun to continue.")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)

def latlon_to_tile(lat, lon, zoom):
    lat_rad = math.radians(lat)
    n = 2.0 ** zoom
    xtile = int((lon + 180.0) / 360.0 * n)
    ytile = int((1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * n)
    return (xtile, ytile)

def meters_to_degrees(meters, latitude):
    lat_deg = meters / 111320.0
    lon_deg = meters / (111320.0 * math.cos(math.radians(latitude)))
    return lat_deg, lon_deg

def get_next_server():
    global server_idx
    with server_lock:
        server = MT_SERVERS[server_idx % len(MT_SERVERS)]
        server_idx += 1
        return server

def get_tile_dir(tile_type):
    return os.path.join(TILE_BASE, tile_type)

def get_full_bounds():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT MIN(latitude), MAX(latitude), MIN(longitude), MAX(longitude) FROM networks')
    result = cursor.fetchone()
    conn.close()

    if not result or None in result:
        return None

    min_lat, max_lat, min_lon, max_lon = result
    return {
        'min_lat': min_lat - AREA_BUFFER,
        'max_lat': max_lat + AREA_BUFFER,
        'min_lon': min_lon - AREA_BUFFER,
        'max_lon': max_lon + AREA_BUFFER
    }

def get_detail_tiles(zoom):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT latitude, longitude FROM networks WHERE latitude IS NOT NULL AND longitude IS NOT NULL')
    points = cursor.fetchall()
    conn.close()

    tile_set = set()
    for lat, lon in points:
        lat_buf, lon_buf = meters_to_degrees(DETAIL_BUFFER_M, lat)
        min_x, min_y = latlon_to_tile(lat + lat_buf, lon - lon_buf, zoom)
        max_x, max_y = latlon_to_tile(lat - lat_buf, lon + lon_buf, zoom)
        for x in range(min_x, max_x + 1):
            for y in range(min_y, max_y + 1):
                tile_set.add((x, y))

    return list(tile_set)

def download_tile(x, y, zoom, tile_type):
    if shutdown_flag:
        return 'stopped'

    tile_dir = Path(get_tile_dir(tile_type)) / str(zoom) / str(x)
    tile_path = tile_dir / f"{y}.png"

    if tile_path.exists() and tile_path.stat().st_size > 0:
        with stats_lock:
            stats['skipped'] += 1
        return 'skipped'

    server = get_next_server()
    url = f"https://{server}.google.com/vt/lyrs={tile_type}&x={x}&y={y}&z={zoom}"

    try:
        response = requests.get(url, timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        if response.status_code == 200 and len(response.content) > 100:
            tile_dir.mkdir(parents=True, exist_ok=True)
            with open(tile_path, 'wb') as f:
                f.write(response.content)
            with stats_lock:
                stats['downloaded'] += 1
                stats['total_bytes'] += len(response.content)
            return 'downloaded'
        else:
            with stats_lock:
                stats['failed'] += 1
            return 'failed'
    except Exception:
        with stats_lock:
            stats['failed'] += 1
        return 'failed'

def download_batch(tiles, zoom_label, tile_type):
    total = len(tiles)
    if total == 0:
        return

    with stats_lock:
        stats['downloaded'] = 0
        stats['skipped'] = 0
        stats['failed'] = 0
        stats['total_bytes'] = 0
        stats['start_time'] = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_tile, x, y, z, tile_type): (x, y, z) for x, y, z in tiles}

        last_update = time.time()
        for completed, future in enumerate(as_completed(futures), 1):
            if shutdown_flag:
                executor.shutdown(wait=False, cancel_futures=True)
                break

            now = time.time()
            if now - last_update >= 1.0:
                with stats_lock:
                    elapsed = now - stats['start_time']
                    done = stats['downloaded'] + stats['skipped']
                    rate = done / elapsed if elapsed > 0 else 0
                    mb = stats['total_bytes'] / 1024 / 1024
                    pct = (completed / total) * 100
                    eta = (total - completed) / rate / 60 if rate > 0 else 0
                    print(f"\r   {zoom_label}: {pct:.1f}% | {stats['downloaded']:,} new | "
                          f"{stats['skipped']:,} cached | {rate:.0f}/s | "
                          f"{mb:.1f} MB | ETA: {eta:.0f}m", end='', flush=True)
                last_update = now

    with stats_lock:
        elapsed = time.time() - stats['start_time']
        mb = stats['total_bytes'] / 1024 / 1024
        print(f"\n   Done: {stats['downloaded']:,} downloaded, {stats['skipped']:,} cached, "
              f"{stats['failed']:,} failed ({mb:.1f} MB in {elapsed/60:.1f}m)")

def main():
    print("=" * 60)
    print("  OFFLINE TILE DOWNLOADER")
    print("=" * 60)

    bounds = get_full_bounds()
    if not bounds:
        print("\n  No wardrive data in database.")
        return

    print(f"\n  Database bounds:")
    print(f"    Lat: {bounds['min_lat']:.4f} to {bounds['max_lat']:.4f}")
    print(f"    Lon: {bounds['min_lon']:.4f} to {bounds['max_lon']:.4f}")
    print(f"    Buffer: {AREA_BUFFER} degrees (~{AREA_BUFFER * 69:.0f} miles)")

    # Build tile list
    all_tiles = []
    print(f"\n  Calculating tiles...")

    for zoom in FULL_ZOOM:
        min_x, min_y = latlon_to_tile(bounds['max_lat'], bounds['min_lon'], zoom)
        max_x, max_y = latlon_to_tile(bounds['min_lat'], bounds['max_lon'], zoom)
        count = 0
        for x in range(min_x, max_x + 1):
            for y in range(min_y, max_y + 1):
                all_tiles.append((x, y, zoom))
                count += 1
        if zoom >= 10:
            print(f"    Zoom {zoom:2d}: {count:>10,} tiles")

    for zoom in DETAIL_ZOOM:
        detail = get_detail_tiles(zoom)
        for x, y in detail:
            all_tiles.append((x, y, zoom))
        print(f"    Zoom {zoom:2d}: {len(detail):>10,} tiles (data areas only)")

    total_per_type = len(all_tiles)
    total_all = total_per_type * len(TILE_TYPES)
    est_gb = total_all * 25 / 1024 / 1024

    print(f"\n  Tiles per type: {total_per_type:,}")
    print(f"  Types: {', '.join(f'{v} ({k})' for k, v in TILE_TYPES.items())}")
    print(f"  Grand total: {total_all:,} tiles")
    print(f"  Estimated size: ~{est_gb:.1f} GB")
    print(f"  Workers: {MAX_WORKERS} threads across {len(MT_SERVERS)} servers")

    response = input(f"\n  Start download? (y/n): ").strip().lower()
    if response != 'y':
        print("  Cancelled.")
        return

    start = time.time()

    for tile_type, type_name in TILE_TYPES.items():
        if shutdown_flag:
            break
        print(f"\n{'=' * 60}")
        print(f"  Downloading {type_name} tiles (lyrs={tile_type})")
        print(f"  Saving to: {get_tile_dir(tile_type)}/")
        print(f"{'=' * 60}")

        for zoom in range(min(FULL_ZOOM), max(DETAIL_ZOOM) + 1):
            if shutdown_flag:
                break
            zoom_tiles = [(x, y, z) for x, y, z in all_tiles if z == zoom]
            if zoom_tiles:
                print(f"\n  Zoom {zoom} ({len(zoom_tiles):,} tiles):")
                download_batch(zoom_tiles, f"Zoom {zoom}", tile_type)

    elapsed = time.time() - start
    hours = elapsed / 3600

    if shutdown_flag:
        print(f"\n\n  Stopped after {hours:.1f} hours. Rerun to continue.")
    else:
        total_mb = 0
        for tile_type in TILE_TYPES:
            td = Path(get_tile_dir(tile_type))
            if td.exists():
                total_mb += sum(f.stat().st_size for f in td.rglob('*.png')) / 1024 / 1024
        print(f"\n{'=' * 60}")
        print(f"  DOWNLOAD COMPLETE")
        print(f"  Total size on disk: {total_mb/1024:.1f} GB")
        print(f"  Time: {hours:.1f} hours")
        print(f"{'=' * 60}")

if __name__ == "__main__":
    main()
