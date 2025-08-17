#!/usr/bin/env python3
"""
Script to update the VERSION file for releases
Usage: python update_version.py <new_version>
Example: python update_version.py 0.9.0
"""

import sys
from pathlib import Path

def update_version(new_version):
    """Update the VERSION file with the new version"""
    version_file = Path("VERSION")
    
    # Validate version format (simple check)
    if not new_version or '.' not in new_version:
        print("Error: Invalid version format. Use format like '0.9.0'")
        sys.exit(1)
    
    # Write new version
    with open(version_file, 'w') as f:
        f.write(new_version + '\n')
    
    print(f"✅ Updated VERSION file to {new_version}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python update_version.py <new_version>")
        print("Example: python update_version.py 0.9.0")
        sys.exit(1)
    
    new_version = sys.argv[1]
    update_version(new_version)
