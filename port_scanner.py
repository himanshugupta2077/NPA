#!/usr/bin/env python3
import os
import json
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from config import BASE_DIR, DATA_DIR, OPEN_PORT_DIR, COMMON_PORT_DIR, FULL_PORT_DIR, FULL_PORT_PN_DIR, load_state, save_state, update_state_metadata, get_timestamp

# Constants - DO NOT CHANGE THESE PORTS
COMMON_PORTS = "21,22,23,25,53,80,88,110,111,123,135,137,138,139,143,161,162,389,443,445,464,514,636,873,902,912,1025,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,8000,8080,8443,9000,9090"

def ensure_directories():
    """Create necessary directories if they don't exist"""
    os.makedirs(COMMON_PORT_DIR, exist_ok=True)
    os.makedirs(FULL_PORT_DIR, exist_ok=True)
    os.makedirs(FULL_PORT_PN_DIR, exist_ok=True)

def get_alive_hosts(state):
    """Extract alive hosts from state"""
    alive_hosts = []
    for target, data in state.get("hosts", {}).items():
        if data.get("alive", False):
            alive_hosts.append(target)
    return alive_hosts

def get_non_alive_hosts(state):
    """Extract non-alive hosts from state"""
    non_alive_hosts = []
    for target, data in state.get("hosts", {}).items():
        if not data.get("alive", False):
            non_alive_hosts.append(target)
    return non_alive_hosts

def run_rustscan_common_ports(targets, timestamp):
    """Run rustscan on common ports"""
    try:
        if not targets:
            return {}
        
        results = {}
        
        for target in targets:
            print(f"[*] Running common port scan on {target}...")
            
            # Expand the ~ to full home directory path
            rustscan_path = os.path.expanduser('~/.cargo/bin/rustscan')
            
            # Check if rustscan exists
            if not os.path.exists(rustscan_path):
                print(f"    Error: rustscan not found at {rustscan_path}")
                results[target] = []
                continue
            
            # Construct rustscan command exactly as specified
            cmd = [
                rustscan_path,
                '-a', target,
                '-p', COMMON_PORTS,
                '--ulimit', '5000',
                '-b', '10',
                '--no-banner',
                '-g'
            ]
            
            output_file = os.path.join(COMMON_PORT_DIR, f'rustscan_{target}_{timestamp}.txt')
            
            try:
                with open(output_file, 'w') as f:
                    result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
                
                # Parse rustscan output
                open_ports = parse_rustscan_output(output_file)
                results[target] = open_ports
                
                if open_ports:
                    print(f"    Found open ports: {open_ports}")
                else:
                    print(f"    No open ports found")
                    
            except subprocess.TimeoutExpired:
                print(f"    Rustscan timeout for {target}")
                results[target] = []
            except Exception as e:
                print(f"    Error running rustscan on {target}: {str(e)}")
                results[target] = []
        
        return results
        
    except Exception as e:
        print(f"Error in rustscan common ports: {str(e)}")
        return {}

def parse_rustscan_output(output_file):
    """Parse rustscan output to extract open ports"""
    try:
        open_ports = []
        with open(output_file, 'r') as f:
            for line in f:
                # Look for lines like "192.168.130.59 -> [445,3306,8080,21,22,80]"
                if ' -> [' in line and ']' in line:
                    port_section = line.split(' -> [')[1].split(']')[0]
                    ports = [int(p.strip()) for p in port_section.split(',') if p.strip().isdigit()]
                    open_ports.extend(ports)
        
        return sorted(list(set(open_ports)))  # Remove duplicates and sort
    except Exception as e:
        print(f"Error parsing rustscan output: {str(e)}")
        return []

def create_target_list_file(targets, filename):
    """Create a temporary file with target list"""
    try:
        with open(filename, 'w') as f:
            f.write('\n'.join(targets))
        return True
    except Exception as e:
        print(f"Error creating target list file: {str(e)}")
        return False

def get_excluded_ports_string(common_ports):
    """Convert common ports string to format suitable for rustscan exclusion"""
    try:
        # Convert common ports to a set for exclusion
        excluded_ports = set(common_ports.split(','))
        return ','.join(sorted(excluded_ports))
    except Exception as e:
        print(f"Error processing excluded ports: {str(e)}")
        return common_ports

def run_rustscan_full_port_scan(targets, timestamp):
    """Run rustscan full port scan on all ports (1-65535)"""
    try:
        if not targets:
            return {}
        
        results = {}
        
        for target in targets:
            print(f"[*] Running full port scan on {target}...")
            
            # Expand the ~ to full home directory path
            rustscan_path = os.path.expanduser('~/.cargo/bin/rustscan')
            
            # Check if rustscan exists
            if not os.path.exists(rustscan_path):
                print(f"    Error: rustscan not found at {rustscan_path}")
                results[target] = []
                continue
            
            # Construct rustscan command for full port range
            cmd = [
                rustscan_path,
                '-a', target,
                '-p', '1-65535',  # Full port range
                '--ulimit', '5000',
                '-b', '50',  # Increased batch size for full scan
                '--no-banner',
                '-g'
            ]
            
            output_file = os.path.join(FULL_PORT_DIR, f'rustscan_full_{target}_{timestamp}.txt')
            
            try:
                with open(output_file, 'w') as f:
                    result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)  # 10 minute timeout
                
                # Parse rustscan output
                open_ports = parse_rustscan_output(output_file)
                
                # Filter out common ports that were already scanned
                common_ports_list = [int(p.strip()) for p in COMMON_PORTS.split(',')]
                filtered_ports = [port for port in open_ports if port not in common_ports_list]
                
                results[target] = filtered_ports
                
                if filtered_ports:
                    print(f"    Found new open ports (excluding common): {filtered_ports}")
                else:
                    print(f"    No new ports found beyond common ports")
                    
            except subprocess.TimeoutExpired:
                print(f"    Rustscan full scan timeout for {target}")
                results[target] = []
            except Exception as e:
                print(f"    Error running rustscan full scan on {target}: {str(e)}")
                results[target] = []
        
        return results
        
    except Exception as e:
        print(f"Error in rustscan full port scan: {str(e)}")
        return {}

def run_nmap_service_scan(targets_with_ports, timestamp, scan_phase=""):
    """Run nmap service version scan on specified ports for given targets"""
    try:
        if not targets_with_ports:
            print(f"[*] No open ports found for service scanning in {scan_phase}")
            return {}
        
        print(f"[*] Running service version scan on {len(targets_with_ports)} targets ({scan_phase})...")
        
        results = {}
        
        for target, ports in targets_with_ports.items():
            if not ports:
                continue
                
            print(f"[*] Scanning services on {target} (ports: {','.join(map(str, ports[:5]))}{'...' if len(ports) > 5 else ''})")
            
            # Create nmap command
            output_prefix = os.path.join(COMMON_PORT_DIR if "common" in scan_phase.lower() else FULL_PORT_DIR, 
                                       f'nmap_sV_{target}_{scan_phase}_{timestamp}')
            cmd = [
                'nmap',
                '-sV', '-O',
                '-p', ','.join(map(str, ports)),
                target,
                '-oA', output_prefix
            ]
            
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Parse nmap XML output for services
                xml_file = output_prefix + '.xml'
                services = parse_nmap_service_output(xml_file)
                results[target] = services
                
                if services:
                    print(f"    Found services: {list(services.keys())}")
                else:
                    print(f"    No detailed service info extracted")
                
            except subprocess.TimeoutExpired:
                print(f"    Service scan timeout for {target}")
                results[target] = {}
            except Exception as e:
                print(f"    Error running service scan on {target}: {str(e)}")
                results[target] = {}
        
        return results
        
    except Exception as e:
        print(f"Error in nmap service scan: {str(e)}")
        return {}

def parse_nmap_service_output(xml_file):
    """Parse nmap XML output for service information"""
    try:
        if not os.path.exists(xml_file):
            return {}
        
        from xml.etree import ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        services = {}
        
        for host in root.findall('host'):
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    port_id = port.get('portid')
                    state = port.find('state')
                    
                    if state is not None and state.get('state') == 'open':
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_info = {
                                'name': service_elem.get('name', ''),
                                'version': service_elem.get('version', ''),
                                'product': service_elem.get('product', ''),
                                'extrainfo': service_elem.get('extrainfo', '')
                            }
                            services[int(port_id)] = service_info
        
        return services
        
    except Exception as e:
        print(f"Error parsing nmap service output: {str(e)}")
        return {}

def run_nmap_pn_scan(targets, timestamp):
    """Run nmap Pn scan on non-alive hosts with common ports"""
    try:
        if not targets:
            return {}
        
        print(f"[*] Running Pn scan on {len(targets)} non-alive hosts...")
        
        results = {}
        
        for target in targets:
            print(f"[*] Running Pn scan on {target}...")
            
            # Create nmap Pn command
            output_prefix = os.path.join(FULL_PORT_PN_DIR, f'nmap_pn_{target}_{timestamp}')
            cmd = [
                'nmap',
                '-Pn',  # Skip ping, treat all hosts as online
                '-sS',  # SYN scan
                '-p', COMMON_PORTS,
                target,
                '-oA', output_prefix
            ]
            
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Parse nmap XML output
                xml_file = output_prefix + '.xml'
                open_ports = parse_nmap_pn_output(xml_file)
                
                if open_ports:
                    results[target] = open_ports
                    print(f"    Found open ports: {open_ports}")
                else:
                    print(f"    No open ports found")
                    
            except subprocess.TimeoutExpired:
                print(f"    Nmap Pn scan timeout for {target}")
            except Exception as e:
                print(f"    Error running nmap Pn scan on {target}: {str(e)}")
        
        return results
        
    except Exception as e:
        print(f"Error in nmap Pn scan: {str(e)}")
        return {}

def parse_nmap_pn_output(xml_file):
    """Parse nmap XML output for Pn scan results"""
    try:
        if not os.path.exists(xml_file):
            return []
        
        from xml.etree import ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        open_ports = []
        
        for host in root.findall('host'):
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = int(port.get('portid'))
                        open_ports.append(port_id)
        
        return sorted(open_ports)
        
    except Exception as e:
        print(f"Error parsing nmap Pn output: {str(e)}")
        return []

def update_state_with_port_results(state, port_results, service_results, timestamp, scan_type):
    """Update state with port scanning results"""
    try:
        for target in port_results:
            if target not in state.get("hosts", {}):
                continue
                
            ports = port_results[target]
            if not ports:
                continue
            
            # Initialize ports dict if it doesn't exist
            if "ports" not in state["hosts"][target]:
                state["hosts"][target]["ports"] = {}
            
            # Add new ports
            for port in ports:
                if port not in state["hosts"][target]["ports"]:
                    state["hosts"][target]["ports"][port] = {
                        'state': 'open',
                        'protocol': 'tcp',
                        'discovered_by': []
                    }
                
                # Update discovery method
                if scan_type not in state["hosts"][target]["ports"][port]['discovered_by']:
                    state["hosts"][target]["ports"][port]['discovered_by'].append(scan_type)
            
            # Update services if available
            if target in service_results and service_results[target]:
                if "services" not in state["hosts"][target]:
                    state["hosts"][target]["services"] = {}
                
                state["hosts"][target]["services"].update(service_results[target])
                
                # Add service info to ports
                for port, service_info in service_results[target].items():
                    if port in state["hosts"][target]["ports"]:
                        state["hosts"][target]["ports"][port]['service'] = service_info
        
        # Update scan metadata
        all_open_ports = set()
        for target_data in state["hosts"].values():
            if target_data.get("ports"):
                all_open_ports.update(target_data["ports"].keys())
        
        if scan_type not in state.get("scans", {}):
            state.setdefault("scans", {})[scan_type] = {}
        
        state["scans"][scan_type].update({
            "completed": True,
            "timestamp": timestamp,
            "total_open_ports": len(all_open_ports)
        })
        
        # Update statistics
        state.setdefault("statistics", {})["total_open_ports"] = len(all_open_ports)
        state["statistics"]["services_identified"] = sum(
            len(data.get("services", {})) for data in state["hosts"].values()
        )
        
        return state
        
    except Exception as e:
        print(f"Error updating state with port results: {str(e)}")
        return state

def print_open_ports_summary(results, scan_type):
    """Print summary of open ports found"""
    try:
        all_ports = set()
        for target, ports in results.items():
            all_ports.update(ports)
        
        if all_ports:
            print(f"[+] {scan_type} scan found open ports: {sorted(list(all_ports))}")
        else:
            print(f"[-] {scan_type} scan found no open ports")
            
    except Exception as e:
        print(f"Error printing port summary: {str(e)}")

def run_scan():
    """Main port scanning function"""
    try:
        print("[*] Starting port scanning phase...")
        
        # Ensure directories exist
        ensure_directories()
        
        # Load current state
        state = load_state()
        
        # Check if alive detection was completed
        if not state.get("scans", {}).get("alive_detection", {}).get("completed", False):
            print("[-] Alive detection not completed. Run alive checker first.")
            return False
        
        # Get alive and non-alive hosts
        alive_hosts = get_alive_hosts(state)
        non_alive_hosts = get_non_alive_hosts(state)
        
        if not alive_hosts:
            print("[-] No alive hosts found for port scanning.")
            if non_alive_hosts:
                print("[*] Will proceed with Pn scan on non-alive hosts...")
            else:
                return False
        
        timestamp = get_timestamp()
        
        # Phase 1: Common port scan with rustscan
        if alive_hosts:
            print(f"\n[*] Phase 1: Common port scan on {len(alive_hosts)} alive hosts...")
            common_results = run_rustscan_common_ports(alive_hosts, timestamp)
            print_open_ports_summary(common_results, "Common port")
            
            # Phase 1.5: Service scan on common ports
            if common_results:
                targets_with_common_ports = {target: ports for target, ports in common_results.items() if ports}
                if targets_with_common_ports:
                    service_results_common = run_nmap_service_scan(targets_with_common_ports, timestamp, "common_ports")
                else:
                    service_results_common = {}
            else:
                service_results_common = {}
            
            # Update state with common port and service results
            state = update_state_with_port_results(state, common_results, service_results_common, timestamp, "common_port_scan")
            save_state(state)
            print("[+] State updated after common port scan and service detection")
        else:
            common_results = {}
            service_results_common = {}
        
        # Phase 2: Full port scan with rustscan (all ports 1-65535)
        if alive_hosts:
            print(f"\n[*] Phase 2: Full port scan with rustscan (1-65535, excluding common ports)...")
            full_results = run_rustscan_full_port_scan(alive_hosts, timestamp)
            print_open_ports_summary(full_results, "Full port")
            
            # Phase 2.5: Service scan on newly found ports
            if full_results:
                targets_with_full_ports = {target: ports for target, ports in full_results.items() if ports}
                if targets_with_full_ports:
                    service_results_full = run_nmap_service_scan(targets_with_full_ports, timestamp, "full_ports")
                else:
                    service_results_full = {}
            else:
                service_results_full = {}
            
            # Update state with full port and service results
            state = update_state_with_port_results(state, full_results, service_results_full, timestamp, "full_port_scan")
            save_state(state)
            print("[+] State updated after full port scan and service detection")
        else:
            full_results = {}
            service_results_full = {}
        
        # Show total discovered ports
        all_ports = set()
        for results in [common_results, full_results]:
            for target, ports in results.items():
                all_ports.update(ports)
        if all_ports:
            print(f"[+] Total unique open ports discovered: {sorted(list(all_ports))}")
        
        # Phase 3: Pn scan on non-alive hosts (run by default)
        if non_alive_hosts:
            print(f"\n[*] Phase 3: Running Pn scan on {len(non_alive_hosts)} non-alive hosts...")
            pn_results = run_nmap_pn_scan(non_alive_hosts, timestamp)
            
            if pn_results:
                print(f"[!] Pn scan found responsive hosts that were previously marked as non-alive:")
                for target, ports in pn_results.items():
                    print(f"    {target}: {ports}")
                    
                    # Update state for newly discovered hosts
                    if target in state["hosts"]:
                        state["hosts"][target]["alive"] = True
                        state["hosts"][target]["detection_methods"] = ["Pn_Scan"]
                        if "ports" not in state["hosts"][target]:
                            state["hosts"][target]["ports"] = {}
                        for port in ports:
                            state["hosts"][target]["ports"][port] = {
                                'state': 'open',
                                'protocol': 'tcp',
                                'discovered_by': ['nmap_pn']
                            }
                
                # Update state with Pn scan results
                state = update_state_with_port_results(state, pn_results, {}, timestamp, "pn_scan")
                
                # Update statistics
                state["statistics"]["alive_hosts"] = sum(
                    1 for data in state["hosts"].values() if data.get("alive", False)
                )
                
                state = update_state_metadata(state)
                save_state(state)
                print("[+] State updated after Pn scan")
            else:
                print(f"[-] Pn scan found no responsive hosts among non-alive targets.")
        
        print(f"\n[+] Port scanning phase completed successfully.")
        return True
        
    except KeyboardInterrupt:
        print(f"\n[!] Port scanning interrupted by user.")
        return False
    except Exception as e:
        print(f"[-] Error in port scanning: {str(e)}")
        return False

if __name__ == "__main__":
    run_scan()