#!/usr/bin/env python3
"""
Pre-commit hook script for yamlfmt
Formats YAML files in the detections/ directory only
Cross-platform compatible (Linux, macOS, Windows)
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path


def find_yamlfmt(custom_path=None):
    """Find yamlfmt executable in common locations or use custom path
    
    Args:
        custom_path: Optional path to yamlfmt binary
    
    Returns:
        Path to yamlfmt executable or None if not found
    """
    # If custom path provided, verify and use it
    if custom_path:
        custom_path = Path(custom_path)
        if custom_path.exists():
            return str(custom_path)
        else:
            print(f"ERROR: yamlfmt not found at specified path: {custom_path}")
            return None
    
    # Check if yamlfmt is in PATH
    for cmd in ['yamlfmt', 'yamlfmt.exe']:
        try:
            result = subprocess.run([cmd, '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                return cmd
        except FileNotFoundError:
            pass
    
    # Check common installation paths
    possible_paths = [
        Path.home() / 'go' / 'bin' / 'yamlfmt',
        Path.home() / 'go' / 'bin' / 'yamlfmt.exe',
        Path('/usr/local/bin/yamlfmt'),
        Path('/usr/bin/yamlfmt'),
        # Check in repo yamlfmt-main folder (for development)
        Path(__file__).parent.parent.parent / 'yamlfmt-main' / 'yamlfmt.exe',
    ]
    
    for path in possible_paths:
        if path.exists():
            return str(path)
    
    print("ERROR: yamlfmt not found. Install with: go install github.com/google/yamlfmt/cmd/yamlfmt@latest")
    print("Make sure $GOPATH/bin is in your PATH")
    print(f"Or place yamlfmt.exe in: {Path.home() / 'go' / 'bin'}")
    print("Or use --yamlfmt-path to specify a custom yamlfmt binary location")
    return None


def main():
    """Run yamlfmt on changed YAML files in detections/"""
    # Parse arguments
    parser = argparse.ArgumentParser(description='Pre-commit hook for yamlfmt')
    parser.add_argument('--yamlfmt-path', help='Path to yamlfmt binary')
    parser.add_argument('files', nargs='*', help='Files to format')
    
    args = parser.parse_args()
    files = args.files
    
    if not files:
        return 0
    
    # Filter to only YAML files in detections/
    yaml_files = [
        f for f in files
        if f.startswith('detections/') and f.endswith(('.yml', '.yaml'))
    ]
    
    if not yaml_files:
        return 0
    
    # Find yamlfmt
    yamlfmt = find_yamlfmt(args.yamlfmt_path)
    if not yamlfmt:
        return 1
    
    # Get repo root to find .yamlfmt config
    repo_root = subprocess.run(
        ['git', 'rev-parse', '--show-toplevel'],
        capture_output=True,
        text=True,
        check=True
    ).stdout.strip()
    
    config_path = Path(repo_root) / '.yamlfmt'
    
    # Run yamlfmt on each file
    failed = False
    for file in yaml_files:
        file_path = Path(repo_root) / file
        if not file_path.exists():
            continue
            
        cmd = [yamlfmt]
        if config_path.exists():
            cmd.extend(['-conf', str(config_path)])
        cmd.append(str(file_path))
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[FAIL] yamlfmt failed for {file}:")
            print(result.stderr)
            failed = True
        else:
            print(f"[OK] Formatted: {file}")
    
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
