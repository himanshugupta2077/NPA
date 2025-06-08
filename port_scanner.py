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

def ask_pn_scan():
    """Ask user if they want to run Pn scan on non-alive hosts"""
    while True:
        response = input("\n[?] Do you want to run a Pn scan on non-alive hosts after all scans are done? (y/n): ").strip().lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' for yes or 'n' for no.")

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

def run_naabu_full_port_scan(targets, timestamp):
    """Run naabu full port scan excluding common ports"""
    try:
        if not targets:
            return {}
        
        results = {}
        
        # Create target list file
        target_file = os.path.join(FULL_PORT_DIR, f'targets_{timestamp}.txt')
        if not create_target_list_file(targets, target_file):
            return {}
        
        print(f"[*] Running full port scan (excluding common ports) on {len(targets)} targets...")
        
        # Expand the ~ to full home directory path for naabu
        naabu_path = os.path.expanduser('~/go/bin/naabu')
        
        # Check if naabu exists
        if not os.path.exists(naabu_path):
            print(f"    Error: naabu not found at {naabu_path}")
            os.remove(target_file)
            return {}
        
        # Construct naabu command
        output_file = os.path.join(FULL_PORT_DIR, f'naabu_full_{timestamp}.json')
        cmd = [
            naabu_path,
            '-l', target_file,
            '-p', '-',
            '-ep', COMMON_PORTS,
            '-o', output_file,
            '-j'
        ]
        
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Parse naabu JSON output
            results = parse_naabu_json_output(output_file)
            
            # Clean up target file
            os.remove(target_file)
            
            return results
            
        except subprocess.TimeoutExpired:
            print(f"    Naabu full scan timeout")
            return {}
        except Exception as e:
            print(f"    Error running naabu full scan: {str(e)}")
            return {}
            
    except Exception as e:
        print(f"Error in naabu full port scan: {str(e)}")
        return {}

def parse_naabu_json_output(output_file):
    """Parse naabu JSON output"""
    try:
        results = {}
        
        if not os.path.exists(output_file):
            return results
            
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        ip = data.get('ip')
                        port = data.get('port')
                        
                        if ip and port:
                            if ip not in results:
                                results[ip] = []
                            results[ip].append(int(port))
                    except json.JSONDecodeError:
                        continue
        
        # Sort ports for each host
        for ip in results:
            results[ip] = sorted(list(set(results[ip])))
        
        return results
        
    except Exception as e:
        print(f"Error parsing naabu JSON output: {str(e)}")
        return {}

def run_nmap_service_scan(state, timestamp):
    """Run nmap service version scan on all open ports"""
    try:
        targets_with_ports = {}
        
        # Collect all targets with open ports
        for target, data in state.get("hosts", {}).items():
            if data.get("alive", False) and data.get("ports"):
                open_ports = [str(port) for port in data["ports"].keys()]
                if open_ports:
                    targets_with_ports[target] = open_ports
        
        if not targets_with_ports:
            print("[*] No open ports found for service scanning")
            return {}
        
        print(f"[*] Running service version scan on {len(targets_with_ports)} targets...")
        
        results = {}
        
        for target, ports in targets_with_ports.items():
            print(f"[*] Scanning services on {target} (ports: {','.join(ports[:5])}{'...' if len(ports) > 5 else ''})")
            
            # Create nmap command
            output_prefix = os.path.join(FULL_PORT_DIR, f'nmap_sV_{target}_{timestamp}')
            cmd = [
                'nmap',
                '-sV', '-O',
                '-p', ','.join(ports),
                target,
                '-oA', output_prefix
            ]
            
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Parse nmap XML output for services
                xml_file = output_prefix + '.xml'
                services = parse_nmap_service_output(xml_file)
                results[target] = services
                
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

def run_naabu_pn_scan(targets, timestamp):
    """Run naabu Pn scan on non-alive hosts with common ports"""
    try:
        if not targets:
            return {}
        
        print(f"[*] Running Pn scan on {len(targets)} non-alive hosts...")
        
        # Create target list file
        target_file = os.path.join(FULL_PORT_PN_DIR, f'pn_targets_{timestamp}.txt')
        if not create_target_list_file(targets, target_file):
            return {}
        
        # Expand the ~ to full home directory path for naabu (or use system naabu)
        naabu_path = os.path.expanduser('~/go/bin/naabu')
        
        # If the go/bin version doesn't exist, try system naabu
        if not os.path.exists(naabu_path):
            # Try to find naabu in PATH
            import shutil
            naabu_path = shutil.which('naabu')
            if not naabu_path:
                print(f"    Error: naabu not found in PATH or at ~/go/bin/naabu")
                os.remove(target_file)
                return {}
        
        # Construct naabu Pn command
        output_file = os.path.join(FULL_PORT_PN_DIR, f'naabu_pn_{timestamp}.json')
        cmd = [
            naabu_path,
            '-l', target_file,
            '-Pn',
            '-p', COMMON_PORTS,
            '-o', output_file,
            '-j'
        ]
        
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Parse naabu JSON output
            results = parse_naabu_json_output(output_file)
            
            # Clean up target file
            os.remove(target_file)
            
            return results
            
        except subprocess.TimeoutExpired:
            print(f"    Naabu Pn scan timeout")
            return {}
        except Exception as e:
            print(f"    Error running naabu Pn scan: {str(e)}")
            return {}
            
    except Exception as e:
        print(f"Error in naabu Pn scan: {str(e)}")
        return {}

def update_state_with_port_results(state, common_results, full_results, service_results, timestamp):
    """Update state with port scanning results"""
    try:
        # Merge common and full port results
        all_open_ports = set()
        
        for target in state.get("hosts", {}):
            if target in common_results or target in full_results:
                # Combine ports from both scans
                ports = set()
                if target in common_results:
                    ports.update(common_results[target])
                if target in full_results:
                    ports.update(full_results[target])
                
                # Update host ports
                state["hosts"][target]["ports"] = {}
                for port in sorted(ports):
                    state["hosts"][target]["ports"][port] = {
                        'state': 'open',
                        'protocol': 'tcp',
                        'discovered_by': []
                    }
                    
                    # Track discovery method
                    if target in common_results and port in common_results[target]:
                        state["hosts"][target]["ports"][port]['discovered_by'].append('rustscan_common')
                    if target in full_results and port in full_results[target]:
                        state["hosts"][target]["ports"][port]['discovered_by'].append('naabu_full')
                
                # Update services if available
                if target in service_results:
                    state["hosts"][target]["services"] = service_results[target]
                    for port, service_info in service_results[target].items():
                        if port in state["hosts"][target]["ports"]:
                            state["hosts"][target]["ports"][port].update({
                                'service': service_info
                            })
                
                all_open_ports.update(ports)
        
        # Update scan metadata
        state["scans"]["port_scanning"] = {
            "completed": True,
            "timestamp": timestamp,
            "ports_scanned": sorted(list(all_open_ports)),
            "total_open_ports": len(all_open_ports),
            "methods_used": ["rustscan_common", "naabu_full", "nmap_service"]
        }
        
        # Update statistics
        state["statistics"]["total_open_ports"] = len(all_open_ports)
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
            return False
        
        print(f"[*] Found {len(alive_hosts)} alive hosts for port scanning")
        
        # Ask about Pn scan before starting
        run_pn_scan = False
        if non_alive_hosts:
            run_pn_scan = ask_pn_scan()
        
        timestamp = get_timestamp()
        
        # Phase 1: Common port scan with rustscan
        print(f"\n[*] Phase 1: Common port scan on {len(alive_hosts)} alive hosts...")
        common_results = run_rustscan_common_ports(alive_hosts, timestamp)
        print_open_ports_summary(common_results, "Common port")
        
        # Update state with common port results
        state = update_state_with_port_results(state, common_results, {}, {}, timestamp)
        save_state(state)
        
        # Phase 2: Full port scan with naabu (excluding common ports)
        print(f"\n[*] Phase 2: Full port scan (excluding common ports)...")
        full_results = run_naabu_full_port_scan(alive_hosts, timestamp)
        print_open_ports_summary(full_results, "Full port")
        
        # Update state with full port results
        state = update_state_with_port_results(state, common_results, full_results, {}, timestamp)
        save_state(state)
        
        print(f"\n[+] Most of the open ports are identified.")
        
        # Show all discovered ports
        all_ports = set()
        for results in [common_results, full_results]:
            for target, ports in results.items():
                all_ports.update(ports)
        if all_ports:
            print(f"[+] Total unique open ports discovered: {sorted(list(all_ports))}")
        
        print(f"[*] Now service scan will be started...")
        
        # Phase 3: Service version scan with nmap
        print(f"\n[*] Phase 3: Service version and OS detection scan...")
        service_results = run_nmap_service_scan(state, timestamp)
        
        # Final state update with all results
        state = update_state_with_port_results(state, common_results, full_results, service_results, timestamp)
        state = update_state_metadata(state)
        save_state(state)
        
        print(f"[+] Open ports and services identification completed.")
        
        # Phase 4: Pn scan if requested
        if run_pn_scan and non_alive_hosts:
            print(f"\n[*] Phase 4: Running Pn scan on {len(non_alive_hosts)} non-alive hosts...")
            pn_results = run_naabu_pn_scan(non_alive_hosts, timestamp)
            
            if pn_results:
                print(f"[!] Pn scan found responsive hosts that were previously marked as non-alive:")
                for target, ports in pn_results.items():
                    print(f"    {target}: {ports}")
                    
                    # Update state for newly discovered hosts
                    if target in state["hosts"]:
                        state["hosts"][target]["alive"] = True
                        state["hosts"][target]["detection_methods"] = ["Pn Scan"]
                        state["hosts"][target]["ports"] = {}
                        for port in ports:
                            state["hosts"][target]["ports"][port] = {
                                'state': 'open',
                                'protocol': 'tcp',
                                'discovered_by': ['naabu_pn']
                            }
                
                # Update statistics
                state["statistics"]["alive_hosts"] = sum(
                    1 for data in state["hosts"].values() if data.get("alive", False)
                )
                
                state = update_state_metadata(state)
                save_state(state)
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