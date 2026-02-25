#!/usr/bin/env python3
"""
GeoIP Database Downloader
Downloads MaxMind GeoLite2 databases for offline IP geolocation
"""

import os
import sys
import argparse
import tarfile
import requests
from pathlib import Path

GEOIP_DIR = '/var/lib/GeoIP'
MAXMIND_DOWNLOAD_URL = 'https://download.maxmind.com/app/geoip_download'


def download_database(license_key: str, edition_id: str, output_dir: str):
    """
    Download and extract MaxMind database

    Args:
        license_key: MaxMind license key
        edition_id: Database edition (GeoLite2-City, GeoLite2-ASN, etc.)
        output_dir: Output directory for database files
    """
    print(f"Downloading {edition_id}...")

    # Construct download URL
    url = f"{MAXMIND_DOWNLOAD_URL}?edition_id={edition_id}&license_key={license_key}&suffix=tar.gz"

    # Download
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()

        # Save to temporary file
        tar_file = os.path.join(output_dir, f"{edition_id}.tar.gz")

        with open(tar_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        print(f"Downloaded {edition_id}.tar.gz")

        # Extract
        print(f"Extracting {edition_id}...")
        with tarfile.open(tar_file, 'r:gz') as tar:
            # Find the .mmdb file
            mmdb_file = None
            for member in tar.getmembers():
                if member.name.endswith('.mmdb'):
                    mmdb_file = member
                    break

            if mmdb_file:
                # Extract to output directory with simplified name
                mmdb_file.name = os.path.basename(mmdb_file.name)
                tar.extract(mmdb_file, output_dir)
                print(f"Extracted {mmdb_file.name} to {output_dir}")
            else:
                print(f"Warning: No .mmdb file found in {edition_id} archive")

        # Clean up tar file
        os.remove(tar_file)
        print(f"Cleaned up {edition_id}.tar.gz")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print(f"Error: Invalid license key or unauthorized")
        else:
            print(f"Error downloading {edition_id}: HTTP {e.response.status_code}")
        return False
    except Exception as e:
        print(f"Error downloading {edition_id}: {e}")
        return False

    return True


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Download MaxMind GeoLite2 databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download both City and ASN databases
  sudo python3 download_geoip.py --license-key YOUR_LICENSE_KEY

  # Download to custom directory
  python3 download_geoip.py --license-key YOUR_LICENSE_KEY --output-dir ./geoip

To get a free license key:
  1. Sign up at https://www.maxmind.com/en/geolite2/signup
  2. Generate a license key at https://www.maxmind.com/en/accounts/current/license-key
        """
    )

    parser.add_argument(
        '--license-key',
        required=True,
        help='MaxMind license key (get free at https://www.maxmind.com/en/geolite2/signup)'
    )

    parser.add_argument(
        '--output-dir',
        default=GEOIP_DIR,
        help=f'Output directory for databases (default: {GEOIP_DIR})'
    )

    parser.add_argument(
        '--city',
        action='store_true',
        help='Download only GeoLite2-City database'
    )

    parser.add_argument(
        '--asn',
        action='store_true',
        help='Download only GeoLite2-ASN database'
    )

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"Output directory: {output_dir}")
    except PermissionError:
        print(f"Error: Permission denied to create {output_dir}")
        print("Try running with sudo or choose a different output directory")
        sys.exit(1)

    # Determine which databases to download
    databases = []
    if args.city and not args.asn:
        databases = ['GeoLite2-City']
    elif args.asn and not args.city:
        databases = ['GeoLite2-ASN']
    else:
        # Download both by default
        databases = ['GeoLite2-City', 'GeoLite2-ASN']

    print(f"Downloading {len(databases)} database(s)...")
    print()

    # Download databases
    success = True
    for db in databases:
        if not download_database(args.license_key, db, str(output_dir)):
            success = False
        print()

    if success:
        print("✓ All databases downloaded successfully!")
        print()
        print("Database locations:")
        for db in databases:
            db_path = output_dir / f"{db}.mmdb"
            if db_path.exists():
                print(f"  - {db_path}")

        print()
        print("Update your honeypot_config.yaml:")
        print("  enrichment:")
        print("    geoip:")
        print("      enabled: true")
        print(f"      database_path: {output_dir}/GeoLite2-City.mmdb")
        print(f"      asn_database_path: {output_dir}/GeoLite2-ASN.mmdb")

    else:
        print("⚠ Some databases failed to download")
        sys.exit(1)


if __name__ == '__main__':
    main()
