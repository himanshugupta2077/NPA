#!/usr/bin/env python3
import sys
import os
from pathlib import Path
from env_setup import init_env
from scope_input import main as scope_input_main
from alive_checker import check_alive, get_alive_hosts_summary
from port_scanner import run_scan as port_scan_main
from config import load_state, STATE_FILE

def print_banner():
    print("=== Pentest Framework ===")
    print("Automated Security Assessment Tool\n")

def print_alive_summary():
    """Print summary of alive hosts from state"""
    try:
        alive_hosts = get_alive_hosts_summary()
        
        if alive_hosts:
            print(f"\n[+] Alive Hosts Summary ({len(alive_hosts)} found):")
            for host in alive_hosts:
                target = host['target']
                methods = ", ".join(host['detection_methods'])
                print(f"  - {target} (Detected by: {methods})")
        else:
            print("\n[-] No alive hosts found.")
            
    except Exception as e:
        print(f"[-] Error printing summary: {str(e)}")

def print_port_summary():
    """Print summary of port scanning results from state"""
    try:
        state = load_state()
        
        # Count hosts with open ports
        hosts_with_ports = 0
        total_open_ports = 0
        unique_ports = set()
        
        for target, data in state.get("hosts", {}).items():
            ports = data.get("ports", {})
            if ports:
                hosts_with_ports += 1
                total_open_ports += len(ports)
                unique_ports.update(ports.keys())
        
        if hosts_with_ports > 0:
            print(f"\n[+] Port Scanning Summary:")
            print(f"    - Hosts with open ports: {hosts_with_ports}")
            print(f"    - Total open ports: {total_open_ports}")
            print(f"    - Unique ports found: {sorted(list(unique_ports))}")
        else:
            print(f"\n[-] No open ports found during scanning.")
            
    except Exception as e:
        print(f"[-] Error printing port summary: {str(e)}")

def print_state_summary():
    """Print overall state summary"""
    try:
        state = load_state()
        
        print(f"\n[+] Current State Summary:")
        print(f"    - State file: {STATE_FILE}")
        print(f"    - Total targets: {state['statistics']['total_targets']}")
        print(f"    - Alive hosts: {state['statistics']['alive_hosts']}")
        print(f"    - Total open ports: {state['statistics']['total_open_ports']}")
        print(f"    - Services identified: {state['statistics']['services_identified']}")
        print(f"    - Scope completed: {'Yes' if state['scope']['normalized_entries'] else 'No'}")
        print(f"    - Alive detection completed: {'Yes' if state['scans']['alive_detection']['completed'] else 'No'}")
        print(f"    - Port scanning completed: {'Yes' if state['scans']['port_scanning']['completed'] else 'No'}")
        print(f"    - Last updated: {state['metadata']['last_updated']}")
        
    except Exception as e:
        print(f"[-] Error getting state summary: {str(e)}")

def main():
    """Main execution flow with clean exit handling"""
    try:
        print_banner()
        
        # Step 0: Environment Setup (CRITICAL - Must be first)
        if not init_env():
            print("\n[!] CRITICAL: Environment setup failed. Cannot proceed.")
            print("[!] Please resolve the issues above and try again.")
            sys.exit(1)
        
        # Step 1: Get scope input
        print("=== PHASE 1: SCOPE DEFINITION ===")
        scope_success = scope_input_main()
        if not scope_success:
            print("\n[-] Scope definition failed. Exiting.")
            sys.exit(1)
        
        print(f"\n[+] Scope processing complete.")
        
        # Step 2: Alive host detection
        print("\n=== PHASE 2: HOST DISCOVERY ===")
        alive_success = check_alive()
        if not alive_success:
            print("\n[-] Host discovery failed. Exiting.")
            sys.exit(1)
        
        # Print alive hosts summary
        print_alive_summary()
        
        # Step 3: Port scanning
        print("\n=== PHASE 3: PORT SCANNING ===")
        port_success = port_scan_main()
        if not port_success:
            print("\n[-] Port scanning failed. Exiting.")
            sys.exit(1)
        
        # Print port scanning summary
        print_port_summary()
        
        # Step 4: Vulnerability scanning (placeholder for next phase)
        print("\n=== PHASE 4: VULNERABILITY SCANNING ===")
        print("[*] Vulnerability scanning module coming soon...")
        
        # Print final state summary
        print_state_summary()
        
        print("\n[+] Pentest framework execution completed successfully.")
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n\n[!] Operation cancelled by user. Exiting.")
        print("\nBye bye!")
        sys.exit(1)
    except SystemExit as e:
        # Let system exits pass through
        raise e
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()