import os
import sys
import re
import ipaddress
import argparse
from urllib.parse import urlparse
from datetime import datetime
from config import BASE_DIR, SCOPE_DIR, USER_SCOPE_DIR, NORMALIZED_SCOPE_DIR, load_state, save_state, update_state_metadata, get_timestamp

# Ensure directories exist
os.makedirs(USER_SCOPE_DIR, exist_ok=True)
os.makedirs(NORMALIZED_SCOPE_DIR, exist_ok=True)

def get_scope_filename(prefix=""):
    """Generate a timestamped scope filename"""
    return f"{prefix}scope_{get_timestamp()}.txt"

def is_valid_ip(entry):
    """Validate IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(entry)
        return True
    except ValueError:
        return False

def is_valid_cidr(entry):
    """Validate CIDR notation (IPv4 or IPv6)"""
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False

def is_valid_url(entry):
    """Basic URL validation"""
    try:
        result = urlparse(entry)
        if not all([result.scheme, result.netloc]):
            return False
        if result.scheme not in ('http', 'https'):
            return False
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', result.netloc):
            return False
        return True
    except:
        return False

def is_valid_hostname(entry):
    """Validate basic hostname (without http://)"""
    if not entry:
        return False
    if len(entry) > 255:
        return False
    if entry[-1] == ".":
        entry = entry[:-1]
    allowed = re.compile(r"^[a-zA-Z0-9-.]*$", re.IGNORECASE)
    return all(allowed.match(x) for x in entry.split("."))

def normalize_target(target):
    """Normalize a single target entry with proper IPv6 handling"""
    if not target.strip():
        return None
    
    target = target.strip()
    
    # Handle URLs
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        target = parsed.netloc
    
    # Special handling for IPv6 addresses
    if ':' in target and ']' not in target:  # IPv6 without port
        # Check if it's an IPv6 CIDR
        if '/' in target and is_valid_cidr(target):
            return target
        # Check if it's a plain IPv6 address
        elif is_valid_ip(target):
            return target
    
    # Remove port numbers if present (for both IPv4 and IPv6)
    if ':' in target:
        if target.startswith('[') and ']' in target:  # IPv6 with port
            target = target.split(']')[0] + ']'
        elif not is_valid_cidr(target):  # Don't split CIDR notation
            target = target.split(':')[0]
    
    # Remove trailing slashes
    target = target.rstrip('/')
    
    # For domains, ensure lowercase and remove www.
    if not is_valid_ip(target) and not is_valid_cidr(target) and '.' in target:
        target = target.lower()
        if target.startswith('www.'):
            target = target[4:]
    
    return target

def expand_cidr(cidr):
    """Expand CIDR notation into individual IP addresses (IPv4 or IPv6)"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.version == 6:  # For IPv6, just return the network range
            return [str(network.network_address), str(network.broadcast_address)]
        return [str(host) for host in network.hosts()]
    except ValueError:
        return []

def validate_and_normalize_entry(entry):
    """Validate and normalize a single scope entry with IPv6 support"""
    entry = entry.strip()
    if not entry:
        return None
    
    # Special case: IPv6 CIDR notation - preserve exactly as is
    if ':' in entry and '/' in entry and is_valid_cidr(entry):
        return entry
    
    normalized = normalize_target(entry)
    if not normalized:
        return None
    
    # Validate the normalized entry
    if (is_valid_ip(normalized) or 
        is_valid_cidr(normalized) or 
        is_valid_url(normalized) or 
        is_valid_hostname(normalized)):
        return normalized
    
    print(f"Invalid scope entry: {entry} - Must be IP, CIDR, or valid URL")
    return None

def normalize_scope_entries(entries):
    """Normalize and expand a list of scope entries with IPv6 support"""
    normalized_entries = set()
    
    for entry in entries:
        validated = validate_and_normalize_entry(entry)
        if validated:
            if is_valid_cidr(validated):
                if ':' in validated:  # IPv6 CIDR - keep as is
                    normalized_entries.add(validated)
                else:  # IPv4 CIDR - expand
                    expanded = expand_cidr(validated)
                    normalized_entries.update(expanded)
            else:
                normalized_entries.add(validated)
    
    return sorted(normalized_entries)

def get_manual_input():
    """Prompt user for manual scope input with exit option"""
    raw_entries = []
    print("\nEnter scope entries (IPs, CIDRs, or URLs). Enter 'done' when finished or 'exit' to quit:")
    print("Examples:")
    print("  - 192.168.1.1")
    print("  - 10.0.0.0/24")
    print("  - 2001:db8::/32")
    print("  - https://example.com")
    print("  - example.org")
    
    while True:
        entry = input("> ").strip()
        if entry.lower() == 'done':
            if not raw_entries:
                print("No entries provided. Please enter at least one valid scope entry.")
                continue
            break
        elif entry.lower() in ('exit', 'quit'):
            print("\nBye bye!\n")
            sys.exit(0)
            
        if entry:
            raw_entries.append(entry)
    
    return raw_entries

def read_scope_file(filepath=None):
    """Read scope entries from a file"""
    if filepath:
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except IOError as e:
                print(f"Error reading file: {e}")
                sys.exit(1)
        else:
            print(f"File not found or not readable: {filepath}")
            sys.exit(1)
    
    # Interactive mode if no filepath provided
    while True:
        filepath = input("Enter path to scope file (or 'exit' to quit): ").strip()
        if filepath.lower() in ('exit', 'quit'):
            print("\nBye bye!\n")
            sys.exit(0)
        
        if not filepath:
            print("Please enter a file path or 'exit' to quit.")
            continue
            
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except IOError as e:
                print(f"Error reading file: {e}")
        else:
            print(f"File not found or not readable: {filepath}")

def save_scope_to_state(raw_entries, normalized_entries):
    """Save scope data to centralized state file"""
    if not raw_entries or not normalized_entries:
        print("No valid scope entries to save.")
        return False
    
    # Load current state
    state = load_state()
    
    # Update scope data
    timestamp = get_timestamp()
    state["scope"] = {
        "raw_entries": raw_entries,
        "normalized_entries": normalized_entries,
        "total_targets": len(normalized_entries),
        "timestamp": timestamp
    }
    
    # Initialize hosts structure
    state["hosts"] = {}
    for target in normalized_entries:
        state["hosts"][target] = {
            "alive": False,
            "detection_methods": [],
            "ports": {},
            "services": {},
            "last_scan": None
        }
    
    # Update statistics
    state["statistics"]["total_targets"] = len(normalized_entries)
    state = update_state_metadata(state)
    
    # Save state atomically
    if save_state(state):
        print(f"\n[+] Scope data saved to state file")
        print(f"    Total targets: {len(normalized_entries)}")
        return True
    else:
        print("[-] Failed to save scope data to state file")
        return False

def save_legacy_scope_files(raw_entries, normalized_entries):
    """Save scope files in legacy format for backward compatibility"""
    if not raw_entries or not normalized_entries:
        return None
    
    # Save raw user scope
    user_scope_path = os.path.join(USER_SCOPE_DIR, get_scope_filename())
    try:
        with open(user_scope_path, 'w') as f:
            f.write("\n".join(raw_entries) + "\n")
        # print(f"Legacy user scope saved to: {user_scope_path}")
    except IOError as e:
        print(f"Error saving legacy user scope file: {e}")
    
    # Save normalized scope
    normalized_scope_path = os.path.join(NORMALIZED_SCOPE_DIR, get_scope_filename("normalized_"))
    try:
        with open(normalized_scope_path, 'w') as f:
            f.write("\n".join(normalized_entries) + "\n")
        
        # print(f"Legacy normalized scope saved to: {normalized_scope_path}")
        return normalized_scope_path
    except IOError as e:
        print(f"Error saving legacy normalized scope file: {e}")
        return None

def process_scope_entries(raw_entries):
    """Process and save scope entries"""
    normalized_entries = normalize_scope_entries(raw_entries)
    
    # Save to centralized state
    success = save_scope_to_state(raw_entries, normalized_entries)
    if success:
        # Also save legacy files for backward compatibility
        save_legacy_scope_files(raw_entries, normalized_entries)
        return True
    
    return False

def main():
    """Main function for scope input handling"""
    parser = argparse.ArgumentParser(description='Scope Input Handler')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-t', '--targets', nargs='+', help='Manual target input (space-separated)')
    group.add_argument('-f', '--file', help='Path to file containing targets')
    
    args = parser.parse_args()
    
    if args.targets:
        # Process targets from command line
        raw_entries = args.targets
        return process_scope_entries(raw_entries)
    elif args.file:
        # Process targets from file
        raw_entries = read_scope_file(args.file)
        return process_scope_entries(raw_entries)
    else:
        # Interactive mode
        print("\n=== Scope Input Handler ===")
        print("Choose input method:")
        print("1. Manual input")
        print("2. File input")
        print("3. Exit")
        
        while True:
            choice = input("Select option (1-3): ").strip()
            if choice == '1':
                raw_entries = get_manual_input()
                return process_scope_entries(raw_entries)
            elif choice == '2':
                raw_entries = read_scope_file()
                return process_scope_entries(raw_entries)
            elif choice in ('3', 'exit', 'quit'):
                print("\nBye bye!\n")
                sys.exit(0)
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        print("\nBye bye!")
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")