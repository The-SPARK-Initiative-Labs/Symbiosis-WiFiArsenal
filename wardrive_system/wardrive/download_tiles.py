#!/usr/bin/env python3
"""
Google Maps Tile Downloader - Aggressive Parallel Mode
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

# Global stats tracking
stats = {
    'downloaded': 0,
    'skipped': 0,
    'failed': 0,
    'total_bytes': 0,
    'start_time': 0
}
stats_lock = Lock()
shutdown_flag = False

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global shutdown_flag
    print("\n\n⚠️  Download interrupted by user")
    print("📊 Tiles downloaded so far are saved and will be reused next time")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)

def latlon_to_tile(lat, lon, zoom):
    """Convert lat/lon to tile coordinates"""
    lat_rad = math.radians(lat)
    n = 2.0 ** zoom
    xtile = int((lon + 180.0) / 360.0 * n)
    ytile = int((1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * n)
    return (xtile, ytile)

def get_coverage_bounds():
    """Get bounding box from wardrive database"""
    conn = sqlite3.connect('wardrive_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT MIN(latitude), MAX(latitude), MIN(longitude), MAX(longitude) FROM networks')
    result = cursor.fetchone()
    conn.close()
    
    if not result or None in result:
        return None
    
    min_lat, max_lat, min_lon, max_lon = result
    buffer = 0.01
    return {
        'min_lat': min_lat - buffer,
        'max_lat': max_lat + buffer,
        'min_lon': min_lon - buffer,
        'max_lon': max_lon + buffer
    }

def download_tile(x, y, zoom, tile_type='y', output_dir='tiles'):
    """Download a single tile"""
    if shutdown_flag:
        return 'stopped'
    
    tile_dir = Path(output_dir) / tile_type / str(zoom) / str(x)
    tile_dir.mkdir(parents=True, exist_ok=True)
    tile_path = tile_dir / f"{y}.png"
    
    # Skip if exists (no delay)
    if tile_path.exists():
        with stats_lock:
            stats['skipped'] += 1
        return 'skipped'
    
    # Download tile
    url = f"https://mt1.google.com/vt/lyrs={tile_type}&x={x}&y={y}&z={zoom}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            with open(tile_path, 'wb') as f:
                f.write(response.content)
            with stats_lock:
                stats['downloaded'] += 1
                stats['total_bytes'] += len(response.content)
            time.sleep(0.05)  # Rate limit only on downloads
            return 'downloaded'
        else:
            with stats_lock:
                stats['failed'] += 1
            return 'failed'
    except Exception:
        with stats_lock:
            stats['failed'] += 1
        return 'failed'

def download_tiles_parallel(bounds, zoom_levels, tile_type='y', workers=20):
    """Download tiles in parallel"""
    print(f"\n📥 Downloading {tile_type} tiles (zoom {min(zoom_levels)}-{max(zoom_levels)})")
    print(f"   Using {workers} parallel threads")
    
    # Generate all tile coordinates
    tiles_to_download = []
    for zoom in zoom_levels:
        min_x, min_y = latlon_to_tile(bounds['max_lat'], bounds['min_lon'], zoom)
        max_x, max_y = latlon_to_tile(bounds['min_lat'], bounds['max_lon'], zoom)
        
        for x in range(min_x, max_x + 1):
            for y in range(min_y, max_y + 1):
                tiles_to_download.append((x, y, zoom, tile_type))
    
    total_tiles = len(tiles_to_download)
    print(f"   Total tiles: {total_tiles:,}")
    
    # Reset stats
    with stats_lock:
        stats['downloaded'] = 0
        stats['skipped'] = 0
        stats['failed'] = 0
        stats['total_bytes'] = 0
        stats['start_time'] = time.time()
    
    # Download with thread pool
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(download_tile, x, y, zoom, tile_type): (x, y, zoom) 
                  for x, y, zoom, tile_type in tiles_to_download}
        
        last_update = time.time()
        for completed, future in enumerate(as_completed(futures), 1):
            if shutdown_flag:
                executor.shutdown(wait=False, cancel_futures=True)
                break
            
            # Update stats every second
            now = time.time()
            if now - last_update >= 1.0:
                with stats_lock:
                    elapsed = now - stats['start_time']
                    rate = (stats['downloaded'] + stats['skipped']) / elapsed if elapsed > 0 else 0
                    mb_sec = (stats['total_bytes'] / 1024 / 1024) / elapsed if elapsed > 0 else 0
                    percent = (completed / total_tiles) * 100
                    eta = (total_tiles - completed) / rate if rate > 0 else 0
                    
                    print(f"   Progress: {percent:.1f}% | {stats['downloaded']:,} new | {stats['skipped']:,} skipped | "
                          f"{rate:.0f} tiles/s | {mb_sec:.2f} MB/s | ETA: {eta/60:.0f}m", end='\r')
                last_update = now
    
    # Final stats
    with stats_lock:
        elapsed = time.time() - stats['start_time']
        mb_total = stats['total_bytes'] / 1024 / 1024
        print(f"\n   ✅ Complete: {stats['downloaded']:,} downloaded, {stats['skipped']:,} skipped, {stats['failed']} failed")
        print(f"   📊 {mb_total:.1f} MB in {elapsed/60:.1f} minutes")

def main():
    print("=" * 60)
    print("🗺️  AGGRESSIVE TILE DOWNLOADER")
    print("=" * 60)
    
    try:
        bounds = get_coverage_bounds()
        if not bounds:
            print("\n❌ No wardrive data in database")
            input("\nPress Enter to exit...")
            return
        
        print("\nZoom level options:")
        print("  [1] Zoom 18 - Fast (~2-5 min)")
        print("  [2] Zoom 22 - Full detail (~4-8 hours)")
        choice = input("\nChoice (1 or 2): ").strip()
        
        zoom_levels = range(15, 23) if choice == '2' else range(15, 19)
        print(f"Selected: Zoom {max(zoom_levels)}")
        
        # Estimate
        total_estimate = 0
        for zoom in zoom_levels:
            min_x, min_y = latlon_to_tile(bounds['max_lat'], bounds['min_lon'], zoom)
            max_x, max_y = latlon_to_tile(bounds['min_lat'], bounds['max_lon'], zoom)
            total_estimate += (max_x - min_x + 1) * (max_y - min_y + 1)
        
        total_estimate *= 2  # Both sat and street
        print(f"\n📈 Estimated: {total_estimate:,} tiles (~{total_estimate * 40 / 1024:.0f} MB)")
        
        response = input("\n⚠️  Start aggressive download? (y/n): ")
        if response.lower() != 'y':
            return
        
        # Download both types
        download_tiles_parallel(bounds, zoom_levels, tile_type='y', workers=20)
        if not shutdown_flag:
            download_tiles_parallel(bounds, zoom_levels, tile_type='m', workers=20)
        
        if shutdown_flag:
            print("\n\n⚠️  Download stopped - progress saved")
        else:
            print("\n\n✅ All tiles downloaded successfully!")
        
        input("\nPress Enter to close...")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
