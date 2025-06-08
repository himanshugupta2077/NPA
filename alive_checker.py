#!/usr/bin/env python3
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from config import BASE_DIR, DATA_DIR, ALIVE_DIR, SCAN_OUTPUT_DIR, load_state, save_state, update_state_metadata, get_timestamp
import ipaddress

def run_fping_scan(targets, output_file):
    """Run fping scan on targets list"""
    try:
        if not targets:
            return []
        
        # Run fping command with targets passed via stdin
        cmd = ['fping', '-q', '-a']
        with open(output_file, 'w') as out_file:
            # Pass targets as input via stdin
            subprocess.run(cmd, input='\n'.join(targets).encode(), 
                          stdout=out_file, stderr=subprocess.DEVNULL)
        
        # Read alive hosts from output file
        with open(output_file, 'r') as f:
            alive_hosts = [line.strip() for line in f if line.strip()]
        
        return alive_hosts
        
    except Exception as e:
        print(f"Error running fping: {str(e)}")
        return []

def run_nmap_ping_sweep(targets, output_prefix):
    """Run nmap ping sweep (-sn)"""
    try:
        # Create temporary target file
        temp_target_file = output_prefix + '_targets.txt'
        with open(temp_target_file, 'w') as f:
            f.write('\n'.join(targets))
        
        output_base = output_prefix
        cmd = [
            'nmap', '-sn', '-iL', temp_target_file,
            '-oA', output_base
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Clean up temp file
        os.remove(temp_target_file)
        
        # Parse XML output to get alive hosts
        xml_file = output_base + '.xml'
        if os.path.exists(xml_file):
            try:
                from xml.etree import ElementTree as ET
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                alive_hosts = []
                for host in root.findall('host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        address = host.find('address')
                        if address is not None:
                            alive_hosts.append(address.get('addr'))
                return alive_hosts
            except Exception as e:
                print(f"Error parsing nmap XML: {str(e)}")
                return []
        return []
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap ping sweep: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected error in nmap ping sweep: {str(e)}")
        return []

def run_nmap_syn_scan(targets, output_prefix):
    """Run nmap TCP SYN scan (-PS)"""
    try:
        # Create temporary target file
        temp_target_file = output_prefix + '_targets.txt'
        with open(temp_target_file, 'w') as f:
            f.write('\n'.join(targets))
        
        output_base = output_prefix
        cmd = [
            'nmap', '-PS22,80,443', '-iL', temp_target_file,
            '-oA', output_base
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Clean up temp file
        os.remove(temp_target_file)
        
        # Parse XML output
        xml_file = output_base + '.xml'
        if os.path.exists(xml_file):
            try:
                from xml.etree import ElementTree as ET
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                alive_hosts = []
                for host in root.findall('host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        address = host.find('address')
                        if address is not None:
                            alive_hosts.append(address.get('addr'))
                return alive_hosts
            except Exception as e:
                print(f"Error parsing nmap XML: {str(e)}")
                return []
        return []
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap SYN scan: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected error in nmap SYN scan: {str(e)}")
        return []

def run_nmap_ack_scan(targets, output_prefix):
    """Run nmap TCP ACK scan (-PA)"""
    try:
        # Create temporary target file
        temp_target_file = output_prefix + '_targets.txt'
        with open(temp_target_file, 'w') as f:
            f.write('\n'.join(targets))
        
        output_base = output_prefix
        cmd = [
            'nmap', '-PA80,443', '-iL', temp_target_file,
            '-oA', output_base
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Clean up temp file
        os.remove(temp_target_file)
        
        # Parse XML output
        xml_file = output_base + '.xml'
        if os.path.exists(xml_file):
            try:
                from xml.etree import ElementTree as ET
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                alive_hosts = []
                for host in root.findall('host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        address = host.find('address')
                        if address is not None:
                            alive_hosts.append(address.get('addr'))
                return alive_hosts
            except Exception as e:
                print(f"Error parsing nmap XML: {str(e)}")
                return []
        return []
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap ACK scan: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected error in nmap ACK scan: {str(e)}")
        return []

def run_nmap_udp_scan(targets, output_prefix):
    """Run nmap UDP scan (-PU)"""
    try:
        # Create temporary target file
        temp_target_file = output_prefix + '_targets.txt'
        with open(temp_target_file, 'w') as f:
            f.write('\n'.join(targets))
        
        output_base = output_prefix
        cmd = [
            'nmap', '-PU53,161', '-iL', temp_target_file,
            '-oA', output_base
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Clean up temp file
        os.remove(temp_target_file)
        
        # Parse XML output
        xml_file = output_base + '.xml'
        if os.path.exists(xml_file):
            try:
                from xml.etree import ElementTree as ET
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                alive_hosts = []
                for host in root.findall('host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        address = host.find('address')
                        if address is not None:
                            alive_hosts.append(address.get('addr'))
                return alive_hosts
            except Exception as e:
                print(f"Error parsing nmap XML: {str(e)}")
                return []
        return []
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap UDP scan: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected error in nmap UDP scan: {str(e)}")
        return []

def run_netcat_banner_grab(targets, output_file):
    """Run netcat banner grab on common ports"""
    try:
        if not targets:
            return []
        
        alive_hosts = set()
        ports = [22, 80, 443, 21, 25, 3389]  # Common ports to check
        
        with open(output_file, 'w') as out_file:
            for target in targets:
                for port in ports:
                    try:
                        cmd = ['nc', '-vz', '-w', '1', target, str(port)]
                        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
                        
                        # Write output to file
                        out_file.write(f"Target: {target}:{port}\n")
                        out_file.write(result.stdout.decode())
                        out_file.write(result.stderr.decode())
                        out_file.write("\n\n")
                        
                        # If connection succeeded or was reset, host is alive
                        if result.returncode == 0 or "Connection refused" in result.stderr.decode():
                            alive_hosts.add(target)
                    except:
                        continue
        
        return list(alive_hosts)
    except Exception as e:
        print(f"Error running netcat banner grab: {str(e)}")
        return []

def run_nbtscan(targets, output_file):
    """Run nbtscan for NetBIOS/SMB detection"""
    try:
        if not targets:
            return []
        
        # Run nbtscan command
        cmd = ['nbtscan'] + targets
        with open(output_file, 'w') as out_file:
            result = subprocess.run(cmd, stdout=out_file, stderr=subprocess.DEVNULL)
        
        # Parse output for alive hosts
        alive_hosts = set()
        with open(output_file, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('IP address'):
                    parts = line.split()
                    if len(parts) > 0:
                        alive_hosts.add(parts[0])
        
        return list(alive_hosts)
    except Exception as e:
        print(f"Error running nbtscan: {str(e)}")
        return []

def save_alive_hosts_file(state):
    """Create legacy alive.txt file for backward compatibility"""
    try:
        alive_hosts = [target for target, data in state["hosts"].items() 
                      if data.get("alive", False)]
        
        if alive_hosts:
            alive_file = os.path.join(ALIVE_DIR, 'alive.txt')
            with open(alive_file, 'w') as f:
                f.write('\n'.join(alive_hosts))
            print(f"[+] Alive hosts list saved to: {alive_file}")
            return alive_file
        return None
    except Exception as e:
        print(f"Error saving alive hosts file: {str(e)}")
        return None

def update_state_with_alive_results(state, alive_results, timestamp):
    """Update state with alive detection results"""
    # Update scan metadata
    state["scans"]["alive_detection"] = {
        "completed": True,
        "timestamp": timestamp,
        "methods_used": [
            "ICMP Ping (fping)",
            "Ping Sweep (nmap)",
            "TCP SYN Scan (nmap)",
            "TCP ACK Scan (nmap)",
            "UDP Scan (nmap)",
            # "Netcat Banner Grab",
            "NetBIOS/SMB Scan (nbtscan)"
        ],
        "total_alive": 0
    }
    
    # Update host data
    for target in state["hosts"]:
        methods = []
        
        # Check each detection method
        if target in alive_results.get("fping", []):
            methods.append("ICMP Ping (fping)")
        if target in alive_results.get("nmap_ping", []):
            methods.append("Ping Sweep (nmap)")
        if target in alive_results.get("nmap_syn", []):
            methods.append("TCP SYN Scan (nmap)")
        if target in alive_results.get("nmap_ack", []):
            methods.append("TCP ACK Scan (nmap)")
        if target in alive_results.get("nmap_udp", []):
            methods.append("UDP Scan (nmap)")
        # if target in alive_results.get("netcat", []):
        #     methods.append("Netcat Banner Grab")
        if target in alive_results.get("nbtscan", []):
            methods.append("NetBIOS/SMB Scan (nbtscan)")
        
        # Update host status
        if methods:
            state["hosts"][target]["alive"] = True
            state["hosts"][target]["detection_methods"] = methods
            state["hosts"][target]["last_scan"] = timestamp
        else:
            state["hosts"][target]["alive"] = False
            state["hosts"][target]["detection_methods"] = []
    
    # Update statistics
    alive_count = sum(1 for target, data in state["hosts"].items() 
                     if data.get("alive", False))
    state["scans"]["alive_detection"]["total_alive"] = alive_count
    state["statistics"]["alive_hosts"] = alive_count
    
    return state

def check_alive():
    """Main function to check for alive hosts using centralized state"""
    try:
        # Load current state
        state = load_state()
        
        # Check if we have scope data
        if not state.get("scope", {}).get("normalized_entries"):
            print("[-] No scope data found. Run scope input first.")
            return False
        
        targets = state["scope"]["normalized_entries"]
        print(f"[*] Checking {len(targets)} targets for alive hosts...")
        
        timestamp = get_timestamp()
        
        # Run all detection methods
        alive_results = {}
        
        print("\n[*] Running fping scan...")
        fping_output = os.path.join(SCAN_OUTPUT_DIR, f'fping_scan_{timestamp}.txt')
        alive_results["fping"] = run_fping_scan(targets, fping_output)
        
        print("\n[*] Running nmap ping sweep...")
        nmap_ping_prefix = os.path.join(SCAN_OUTPUT_DIR, f'nmap_sn_{timestamp}')
        alive_results["nmap_ping"] = run_nmap_ping_sweep(targets, nmap_ping_prefix)
        
        print("\n[*] Running nmap TCP SYN scan...")
        nmap_syn_prefix = os.path.join(SCAN_OUTPUT_DIR, f'nmap_syn_{timestamp}')
        alive_results["nmap_syn"] = run_nmap_syn_scan(targets, nmap_syn_prefix)
        
        print("\n[*] Running nmap TCP ACK scan...")
        nmap_ack_prefix = os.path.join(SCAN_OUTPUT_DIR, f'nmap_ack_{timestamp}')
        alive_results["nmap_ack"] = run_nmap_ack_scan(targets, nmap_ack_prefix)
        
        print("\n[*] Running nmap UDP scan...")
        nmap_udp_prefix = os.path.join(SCAN_OUTPUT_DIR, f'nmap_udp_{timestamp}')
        alive_results["nmap_udp"] = run_nmap_udp_scan(targets, nmap_udp_prefix)
        
        # print("\n[*] Running netcat banner grab...")
        # netcat_output = os.path.join(SCAN_OUTPUT_DIR, f'netcat_{timestamp}.txt')
        # alive_results["netcat"] = run_netcat_banner_grab(targets, netcat_output)
        
        print("\n[*] Running nbtscan...")
        nbtscan_output = os.path.join(SCAN_OUTPUT_DIR, f'nbtscan_{timestamp}.txt')
        alive_results["nbtscan"] = run_nbtscan(targets, nbtscan_output)
        
        # Update state with results
        state = update_state_with_alive_results(state, alive_results, timestamp)
        state = update_state_metadata(state)
        
        # Save state atomically
        if save_state(state):
            print(f"\n[+] Alive host detection results saved to state file")
            
            # Create legacy alive.txt file
            save_alive_hosts_file(state)
            
            # Print summary
            alive_count = state["statistics"]["alive_hosts"]
            print(f"\n[*] Found {alive_count} alive hosts out of {len(targets)}")
            
            return True
        else:
            print("[-] Failed to save alive detection results")
            return False
    
    except Exception as e:
        print(f"[-] Error in check_alive: {str(e)}")
        return False

def get_alive_hosts_summary():
    """Get summary of alive hosts from state"""
    try:
        state = load_state()
        alive_hosts = []
        
        for target, data in state.get("hosts", {}).items():
            if data.get("alive", False):
                alive_hosts.append({
                    "target": target,
                    "detection_methods": data.get("detection_methods", [])
                })
        
        return alive_hosts
    except Exception as e:
        print(f"Error getting alive hosts summary: {str(e)}")
        return []

if __name__ == "__main__":
    check_alive()