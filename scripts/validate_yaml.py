#!/usr/bin/env python3
"""
CI Validation Script for YAML Files
Runs yamllint and yamlfmt --lint with beautified error output
Usage: python scripts/validate_yaml.py [path_to_yaml_files...]
"""
import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple, Optional


def find_yamlfmt(custom_path: Optional[str] = None) -> Optional[str]:
    """Find yamlfmt executable in common locations or use custom path
    
    Args:
        custom_path: Optional path to yamlfmt binary
    
    Returns:
        Path to yamlfmt executable or None if not found
    """
    # If custom path provided, verify and use it
    if custom_path:
        custom_path_obj = Path(custom_path)
        if custom_path_obj.exists():
            return str(custom_path_obj)
        else:
            print_error(f"yamlfmt not found at specified path: {custom_path}")
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
    ]
    
    for path in possible_paths:
        if path.exists():
            return str(path)
    
    print_error("yamlfmt not found. Install with: go install github.com/google/yamlfmt/cmd/yamlfmt@latest")
    print("Make sure $GOPATH/bin is in your PATH")
    print("Or use --yamlfmt-path to specify a custom yamlfmt binary location")
    return None


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @classmethod
    def disable(cls):
        """Disable colors for non-terminal output"""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ''
        cls.MAGENTA = cls.CYAN = cls.BOLD = cls.RESET = ''


def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text:^80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.RESET}\n")


def print_error(text: str):
    """Print an error message"""
    print(f"{Colors.RED}[ERROR] {text}{Colors.RESET}")


def print_success(text: str):
    """Print a success message"""
    print(f"{Colors.GREEN}[PASS] {text}{Colors.RESET}")


def print_warning(text: str):
    """Print a warning message"""
    print(f"{Colors.YELLOW}[WARN] {text}{Colors.RESET}")


def find_yaml_files(paths: List[str]) -> List[Path]:
    """Find all YAML files in detections/ from given paths"""
    yaml_files = []
    
    for path_str in paths:
        path = Path(path_str)
        
        # Make relative to repo root if absolute
        if path.is_absolute():
            try:
                repo_root = Path(subprocess.run(
                    ['git', 'rev-parse', '--show-toplevel'],
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout.strip())
                path = path.relative_to(repo_root)
            except:
                pass
        
        if path.is_file():
            # Check if path contains 'detections' or if it's in detections/
            path_str_normalized = str(path).replace('\\', '/')
            if 'detections/' in path_str_normalized and path.suffix in ['.yml', '.yaml']:
                yaml_files.append(path)
        elif path.is_dir():
            for yaml_file in path.rglob('*.yml'):
                path_str_normalized = str(yaml_file).replace('\\', '/')
                if 'detections/' in path_str_normalized:
                    yaml_files.append(yaml_file)
            for yaml_file in path.rglob('*.yaml'):
                path_str_normalized = str(yaml_file).replace('\\', '/')
                if 'detections/' in path_str_normalized:
                    yaml_files.append(yaml_file)
    
    return sorted(set(yaml_files))


def run_yamllint(files: List[Path], config: Path) -> Tuple[bool, dict]:
    """Run yamllint on files and return success status and errors by file
    
    Returns:
        Tuple of (success, file_errors_dict)
    """
    if not files:
        return True, {}
    
    # Process files in batches to avoid command line length limits on Windows
    batch_size = 50
    all_file_errors = {}
    all_passed = True
    
    for i in range(0, len(files), batch_size):
        batch = files[i:i + batch_size]
        cmd = ['yamllint', '-c', str(config)] + [str(f) for f in batch]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        
        if result.returncode != 0:
            all_passed = False
            
            # Parse yamllint output
            errors = result.stdout.strip().split('\n')
            current_file = None
            
            for line in errors:
                if not line.strip():
                    continue
                    
                # Check if this is a file path line
                if not line.startswith(' '):
                    current_file = line
                    if current_file not in all_file_errors:
                        all_file_errors[current_file] = []
                else:
                    # This is an error line
                    if current_file:
                        all_file_errors[current_file].append(line.strip())
    
    return all_passed, all_file_errors


def run_yamlfmt_lint(files: List[Path], config: Path, yamlfmt_path: Optional[str] = None) -> Tuple[bool, set]:
    """Run yamlfmt --lint on files and return success status and set of files with issues
    
    Returns:
        Tuple of (success, set_of_unformatted_files)
    """
    if not files:
        return True, set()
    
    # Find yamlfmt executable
    yamlfmt = find_yamlfmt(yamlfmt_path)
    if not yamlfmt:
        return False, set()
    
    # Process files in batches to avoid command line length limits on Windows
    batch_size = 50
    all_unformatted_files = set()
    all_passed = True
    
    for i in range(0, len(files), batch_size):
        batch = files[i:i + batch_size]
        
        # yamlfmt --lint returns non-zero if files need formatting
        cmd = [yamlfmt, '-lint', '-conf', str(config)] + [str(f) for f in batch]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        
        if result.returncode != 0:
            all_passed = False
            
            # Parse yamlfmt output to find files that need formatting
            output = result.stdout.strip()
            
            if output:
                lines = output.split('\n')
                for line in lines:
                    line = line.strip()
                    # yamlfmt outputs the file path, often followed by a colon
                    if (line.endswith('.yml') or line.endswith('.yaml') or 
                        line.endswith('.yml:') or line.endswith('.yaml:')):
                        # Remove trailing colon if present
                        file_path = line.rstrip(':')
                        if file_path:
                            all_unformatted_files.add(file_path)
            
            # If we couldn't parse files from this batch, add all batch files
            if not output and result.returncode != 0:
                all_unformatted_files.update(str(f) for f in batch)
    
    return all_passed, all_unformatted_files


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Validate YAML files with yamllint and yamlfmt',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
  # Validate all detection files
  python scripts/validate_yaml.py detections/

  # Validate specific files
  python scripts/validate_yaml.py detections/endpoint/file.yml

  # Validate changed files (for CI)
  python scripts/validate_yaml.py $(git diff --name-only --diff-filter=ACM origin/develop...HEAD | grep '^detections/.*\.yml$')
        """
    )
    parser.add_argument(
        'paths',
        nargs='*',
        default=['detections/'],
        help='Paths to YAML files or directories to validate (default: detections/)'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '--yamlfmt-path',
        help='Path to yamlfmt binary (useful when Go is not available but standalone binary is)'
    )
    
    args = parser.parse_args()
    
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()
    
    # Find repo root
    try:
        repo_root = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        repo_root = Path(repo_root)
    except (subprocess.CalledProcessError, FileNotFoundError):
        repo_root = Path.cwd()
    
    # Find config files
    yamllint_config = repo_root / '.yamllint'
    yamlfmt_config = repo_root / '.yamlfmt'
    
    if not yamllint_config.exists():
        print_error(f".yamllint config not found at {yamllint_config}")
        return 1
    
    if not yamlfmt_config.exists():
        print_error(f".yamlfmt config not found at {yamlfmt_config}")
        return 1
    
    # Find YAML files
    yaml_files = find_yaml_files(args.paths)
    
    if not yaml_files:
        print_warning("No YAML files found in detections/ directory")
        return 0
    
    print(f"{Colors.BOLD}Found {len(yaml_files)} YAML file(s) to validate{Colors.RESET}")
    
    print_header("Validating YAML Files")
    
    # Run both validations
    yamllint_passed, yamllint_errors = run_yamllint(yaml_files, yamllint_config)
    yamlfmt_passed, yamlfmt_files = run_yamlfmt_lint(yaml_files, yamlfmt_config, args.yamlfmt_path)
    
    # Combine results by file
    all_issues = {}  # file_path -> list of errors
    
    # Add yamllint errors
    for file_path, errors in yamllint_errors.items():
        if file_path not in all_issues:
            all_issues[file_path] = []
        all_issues[file_path].extend(errors)
    
    # Add yamlfmt formatting issues
    for file_path in yamlfmt_files:
        if file_path not in all_issues:
            all_issues[file_path] = []
        all_issues[file_path].append("Formatting differences detected")
    
    # Display combined results
    if not all_issues:
        print_success(f"All {len(yaml_files)} file(s) passed validation!")
        return 0
    
    # Show issues grouped by file
    total_errors = sum(len(errors) for errors in all_issues.values())
    print(f"\n{Colors.RED}[X] Found issues in {len(all_issues)} file(s):{Colors.RESET}\n")
    
    for file_path, errors in sorted(all_issues.items()):
        print(f"  {Colors.BOLD}{Colors.MAGENTA}> {file_path}{Colors.RESET}")
        for error in errors:
            print(f"    {Colors.RED}- {error}{Colors.RESET}")
        print()  # Empty line between files
    
    # Show fix instructions
    print(f"{Colors.CYAN}[TIP] To fix these issues, run:{Colors.RESET}")
    print(f"  {Colors.BOLD}yamlfmt -conf .yamlfmt detections/{Colors.RESET}")
    print(f"\n{Colors.CYAN}      Or for specific files:{Colors.RESET}")
    print(f"  {Colors.BOLD}yamlfmt -conf .yamlfmt <file_path>{Colors.RESET}\n")
    
    return 1


if __name__ == '__main__':
    sys.exit(main())
