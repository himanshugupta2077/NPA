#!/usr/bin/env python3
"""
Environment Setup and Dependency Checker for NPA Framework
Ensures all required tools and dependencies are available before starting scan operations
"""

import os
import sys
import json
import shutil
import subprocess
import platform
from pathlib import Path
from datetime import datetime
from config import load_state, save_state, update_state_metadata, LOGS_FILE

# Required tools and their installation commands
REQUIRED_TOOLS = {
    'nmap': {
        'check_cmd': ['nmap', '--version'],
        'install_cmd': 'sudo apt install -y nmap',
        'description': 'Network Mapper - Port scanning and network discovery',
        'priority': 'critical'
    },
    'fping': {
        'check_cmd': ['fping', '-v'],
        'install_cmd': 'sudo apt install -y fping',
        'description': 'Fast ping utility for network discovery',
        'priority': 'high'
    },
    'nbtscan': {
        'check_cmd': ['nbtscan', '-h'],
        'install_cmd': 'sudo apt install -y nbtscan',
        'description': 'NetBIOS name scanner',
        'priority': 'medium'
    },
    'netcat': {
        'check_cmd': ['nc', '-h'],
        'alt_check_cmd': ['netcat', '-h'],
        'install_cmd': 'sudo apt install -y netcat-traditional',
        'description': 'Network utility for reading/writing network connections',
        'priority': 'high'
    },
    'jq': {
        'check_cmd': ['jq', '--version'],
        'install_cmd': 'sudo apt install -y jq',
        'description': 'JSON processor',
        'priority': 'medium'
    },
    'rustscan': {
        'check_cmd': ['rustscan', '--version'],
        'alt_paths': ['~/.cargo/bin/rustscan'],
        'install_cmd': 'cargo install rustscan',
        'description': 'Fast port scanner written in Rust',
        'priority': 'optional'
    },
    'naabu': {
        'check_cmd': ['naabu', '-version'],
        'alt_paths': ['~/go/bin/naabu'],
        'install_cmd': 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
        'description': 'Fast port scanner from ProjectDiscovery',
        'priority': 'optional'
    },
    'nuclei': {
        'check_cmd': ['nuclei', '-version'],
        'alt_paths': ['~/go/bin/nuclei'],
        'install_cmd': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        'description': 'Vulnerability scanner based on templates',
        'priority': 'optional'
    }
}

# System packages needed for compilation
SYSTEM_PACKAGES = [
    'libpcap-dev',
    'cargo',
    'build-essential'
]

def print_banner():
    """Print environment setup banner"""
    print("=== ENVIRONMENT SETUP ===")
    print("Checking dependencies and preparing environment...\n")

def check_python_version():
    """Check if Python version is >= 3.8"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"[!] ERROR: Python {version.major}.{version.minor} detected.")
        print("[!] Python 3.8 or higher is required.")
        return False
    
    print(f"[+] Python {version.major}.{version.minor}.{version.micro} - OK")
    return True

def check_disk_space():
    """Check available disk space and warn if less than 2GB"""
    try:
        statvfs = os.statvfs(os.getcwd())
        free_bytes = statvfs.f_frsize * statvfs.f_bavail
        free_gb = free_bytes / (1024**3)
        
        print(f"[+] Available disk space: {free_gb:.2f} GB")
        
        if free_gb < 2.0:
            print(f"[!] WARNING: Only {free_gb:.2f} GB available. Recommend at least 2 GB free space.")
            return False
        return True
    except Exception as e:
        print(f"[!] Could not check disk space: {e}")
        return True  # Don't fail on this check

def check_write_permissions():
    """Check write permissions for required directories"""
    from config import BASE_DIR, DATA_DIR, LOGS_DIR
    
    directories_to_check = [BASE_DIR, DATA_DIR, LOGS_DIR]
    
    for directory in directories_to_check:
        try:
            # Try to create a test file
            test_file = os.path.join(directory, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print(f"[+] Write access to {directory} - OK")
        except Exception as e:
            print(f"[!] ERROR: No write access to {directory}: {e}")
            return False
    
    return True

def check_tool_availability(tool_name, tool_config):
    """Check if a tool is available in PATH or alternative locations"""
    # First check if tool is in PATH
    if shutil.which(tool_name):
        try:
            result = subprocess.run(
                tool_config['check_cmd'], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0 or tool_name in ['nbtscan', 'netcat']:  # Some tools return non-zero on help
                return True, shutil.which(tool_name)
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
    
    # Check alternative command for netcat
    if tool_name == 'netcat' and 'alt_check_cmd' in tool_config:
        if shutil.which('netcat'):
            try:
                result = subprocess.run(
                    tool_config['alt_check_cmd'], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                return True, shutil.which('netcat')
            except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                pass
    
    # Check alternative paths
    if 'alt_paths' in tool_config:
        for alt_path in tool_config['alt_paths']:
            expanded_path = os.path.expanduser(alt_path)
            if os.path.exists(expanded_path) and os.access(expanded_path, os.X_OK):
                return True, expanded_path
    
    return False, None

def get_system_info():
    """Gather system information for logging"""
    try:
        system_info = {
            'timestamp': datetime.now().isoformat(),
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            'python_executable': sys.executable,
            'current_user': os.getenv('USER', 'unknown'),
            'working_directory': os.getcwd(),
            'environment_variables': {
                'PATH': os.getenv('PATH', ''),
                'HOME': os.getenv('HOME', ''),
                'SHELL': os.getenv('SHELL', ''),
                'GOPATH': os.getenv('GOPATH', ''),
                'CARGO_HOME': os.getenv('CARGO_HOME', '')
            }
        }
        
        # Get disk space info
        try:
            statvfs = os.statvfs(os.getcwd())
            total_bytes = statvfs.f_frsize * statvfs.f_blocks
            free_bytes = statvfs.f_frsize * statvfs.f_bavail
            system_info['disk_space'] = {
                'total_gb': total_bytes / (1024**3),
                'free_gb': free_bytes / (1024**3)
            }
        except:
            system_info['disk_space'] = 'unavailable'
        
        return system_info
    except Exception as e:
        return {'error': f'Could not gather system info: {e}'}

def dump_system_info():
    """Dump system information to logs file"""
    try:
        system_info = get_system_info()
        
        # Ensure logs directory exists
        os.makedirs(os.path.dirname(LOGS_FILE), exist_ok=True)
        
        with open(LOGS_FILE, 'w') as f:
            json.dump(system_info, f, indent=2)
        
        print(f"[+] System information logged to: {LOGS_FILE}")
        return True
    except Exception as e:
        print(f"[!] Could not dump system info: {e}")
        return False

def get_priority_color(priority):
    """Get color code for priority display"""
    colors = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'optional': '\033[92m'   # Green
    }
    return colors.get(priority, '\033[0m')  # Default

def reset_color():
    """Reset terminal color"""
    return '\033[0m'

def install_system_packages():
    """Install system packages needed for compilation"""
    try:
        print("[*] Installing system packages...")
        cmd = ['sudo', 'apt', 'update']
        subprocess.run(cmd, check=True, capture_output=True)
        
        cmd = ['sudo', 'apt', 'install', '-y'] + SYSTEM_PACKAGES
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] System packages installed successfully")
            return True
        else:
            print(f"[!] Warning: System package installation had issues: {result.stderr}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Warning: Could not install system packages: {e}")
        return False

def install_single_tool(tool_name, tool_config):
    """Install a single tool"""
    try:
        print(f"[*] Installing {tool_name}...")
        install_cmd = tool_config['install_cmd'].split()
        
        result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print(f"[+] {tool_name} installed successfully")
            return True
        else:
            print(f"[!] Failed to install {tool_name}: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print(f"[!] Installation of {tool_name} timed out")
        return False
    except Exception as e:
        print(f"[!] Failed to install {tool_name}: {e}")
        return False

def install_missing_tools(missing_tools):
    """Ask user for each missing tool if they want to install it"""
    if not missing_tools:
        return True
    
    print(f"\n[!] Found {len(missing_tools)} missing tools:")
    
    # Group tools by priority for better display
    priority_groups = {'critical': [], 'high': [], 'medium': [], 'optional': []}
    for tool in missing_tools:
        priority = REQUIRED_TOOLS[tool].get('priority', 'medium')
        priority_groups[priority].append(tool)
    
    # Display tools grouped by priority
    for priority, tools in priority_groups.items():
        if tools:
            color = get_priority_color(priority)
            print(f"\n{color}[{priority.upper()} PRIORITY]{reset_color()}")
            for tool in tools:
                print(f"    - {tool}: {REQUIRED_TOOLS[tool]['description']}")
    
    print(f"\n{'='*60}")
    print("INSTALLATION OPTIONS")
    print(f"{'='*60}")
    
    tools_to_install = []
    system_packages_needed = False
    
    # Ask for each tool individually
    for tool in missing_tools:
        tool_config = REQUIRED_TOOLS[tool]
        priority = tool_config.get('priority', 'medium')
        color = get_priority_color(priority)
        
        print(f"\n{color}[{priority.upper()}]{reset_color()} {tool}")
        print(f"Description: {tool_config['description']}")
        print(f"Install command: {tool_config['install_cmd']}")
        
        # Provide recommendation based on priority
        if priority == 'critical':
            recommendation = " (STRONGLY RECOMMENDED)"
        elif priority == 'high':
            recommendation = " (RECOMMENDED)"
        elif priority == 'medium':
            recommendation = " (USEFUL)"
        else:
            recommendation = " (OPTIONAL)"
        
        while True:
            response = input(f"Install {tool}?{recommendation} (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                tools_to_install.append(tool)
                # Check if this tool needs system packages
                if any(cmd in tool_config['install_cmd'] for cmd in ['cargo', 'go']):
                    system_packages_needed = True
                break
            elif response in ['n', 'no']:
                print(f"[-] Skipping {tool}")
                break
            else:
                print("[!] Please answer 'y' or 'n'")
    
    if not tools_to_install:
        print("\n[!] No tools selected for installation.")
        return False
    
    print(f"\n[*] Selected {len(tools_to_install)} tools for installation:")
    for tool in tools_to_install:
        print(f"    - {tool}")
    
    # Final confirmation
    final_confirm = input(f"\nProceed with installation of {len(tools_to_install)} tools? (y/N): ").strip().lower()
    if final_confirm not in ['y', 'yes']:
        print("[!] Installation cancelled by user.")
        return False
    
    # Install system packages if needed
    if system_packages_needed:
        if not install_system_packages():
            print("[!] Warning: System package installation failed. Some tools may not install correctly.")
    
    # Install selected tools
    print(f"\n[*] Installing {len(tools_to_install)} selected tools...")
    success_count = 0
    failed_tools = []
    
    for tool in tools_to_install:
        if install_single_tool(tool, REQUIRED_TOOLS[tool]):
            success_count += 1
        else:
            failed_tools.append(tool)
    
    # Summary
    print(f"\n{'='*50}")
    print("INSTALLATION SUMMARY")
    print(f"{'='*50}")
    print(f"Successfully installed: {success_count}/{len(tools_to_install)} tools")
    
    if failed_tools:
        print(f"Failed installations:")
        for tool in failed_tools:
            print(f"    - {tool}")
        print(f"\nYou can try installing failed tools manually:")
        for tool in failed_tools:
            print(f"    {REQUIRED_TOOLS[tool]['install_cmd']}")
    
    if success_count > 0:
        print(f"\n[+] {success_count} tools installed successfully!")
        return True
    else:
        print(f"\n[!] No tools were installed successfully.")
        return False

def update_state_with_env_info():
    """Update state file with environment initialization info"""
    try:
        state = load_state()
        
        # Add environment info to metadata
        if 'environment' not in state['metadata']:
            state['metadata']['environment'] = {}
        
        state['metadata']['environment'].update({
            'init_time': datetime.now().isoformat(),
            'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            'platform': platform.platform(),
            'env_setup_completed': True
        })
        
        # Update timestamps
        state = update_state_metadata(state)
        
        # Save state
        if save_state(state):
            print("[+] Environment info saved to state file")
            return True
        else:
            print("[!] Could not save environment info to state file")
            return False
    except Exception as e:
        print(f"[!] Error updating state with environment info: {e}")
        return False

def init_env():
    """Main environment initialization function"""
    print_banner()
    
    success = True
    
    # Step 1: Check Python version
    print("[*] Checking Python version...")
    if not check_python_version():
        print("[!] CRITICAL: Python version check failed")
        return False
    
    # Step 2: Check disk space
    print("\n[*] Checking disk space...")
    if not check_disk_space():
        print("[!] WARNING: Low disk space detected")
    
    # Step 3: Check write permissions
    print("\n[*] Checking write permissions...")
    if not check_write_permissions():
        print("[!] CRITICAL: Write permission check failed")
        return False
    
    # Step 4: Dump system info
    print("\n[*] Logging system information...")
    dump_system_info()
    
    # Step 5: Check tool availability
    print("\n[*] Checking tool availability...")
    available_tools = []
    missing_tools = []
    
    for tool_name, tool_config in REQUIRED_TOOLS.items():
        is_available, tool_path = check_tool_availability(tool_name, tool_config)
        
        if is_available:
            print(f"[+] {tool_name} - Available at {tool_path}")
            available_tools.append(tool_name)
        else:
            priority = tool_config.get('priority', 'medium')
            color = get_priority_color(priority)
            print(f"[-] {tool_name} - Not found {color}[{priority.upper()}]{reset_color()}")
            missing_tools.append(tool_name)
    
    # Step 6: Handle missing tools
    if missing_tools:
        print(f"\n[!] {len(missing_tools)} tools are missing")
        
        # Separate critical/high priority tools
        critical_missing = [t for t in missing_tools if REQUIRED_TOOLS[t].get('priority') == 'critical']
        high_missing = [t for t in missing_tools if REQUIRED_TOOLS[t].get('priority') == 'high']
        
        if critical_missing:
            print(f"\n[!] CRITICAL: {len(critical_missing)} critical tools are missing:")
            for tool in critical_missing:
                print(f"    - {tool}")
            print("[!] Framework functionality will be severely limited without these tools.")
        
        # Offer installation
        install_missing_tools(missing_tools)
        
        # Re-check after installation attempt
        print(f"\n[*] Re-checking tool availability...")
        still_missing = []
        newly_available = []
        
        for tool_name in missing_tools:
            is_available, tool_path = check_tool_availability(tool_name, REQUIRED_TOOLS[tool_name])
            if is_available:
                print(f"[+] {tool_name} - Now available at {tool_path}")
                available_tools.append(tool_name)
                newly_available.append(tool_name)
            else:
                priority = REQUIRED_TOOLS[tool_name].get('priority', 'medium')
                color = get_priority_color(priority)
                print(f"[-] {tool_name} - Still missing {color}[{priority.upper()}]{reset_color()}")
                still_missing.append(tool_name)
        
        if newly_available:
            print(f"\n[+] {len(newly_available)} tools are now available!")
        
        if still_missing:
            critical_still_missing = [t for t in still_missing if REQUIRED_TOOLS[t].get('priority') == 'critical']
            if critical_still_missing:
                print(f"\n[!] CRITICAL: {len(critical_still_missing)} essential tools are still missing:")
                for tool in critical_still_missing:
                    print(f"    - {tool}")
                print("\n[!] Framework cannot operate at full capacity without these tools.")
                success = False
            else:
                print(f"\n[!] {len(still_missing)} non-critical tools are still missing.")
                print("[*] Framework will operate with reduced functionality.")
    else:
        print(f"\n[+] All {len(REQUIRED_TOOLS)} required tools are available!")
    
    # Step 7: Update state file
    print("\n[*] Updating state file with environment info...")
    update_state_with_env_info()
    
    # Final summary
    print(f"\n{'='*60}")
    print("ENVIRONMENT SETUP SUMMARY")
    print(f"{'='*60}")
    print(f"Available tools: {len(available_tools)}/{len(REQUIRED_TOOLS)}")
    print(f"System info logged: {LOGS_FILE}")
    
    if available_tools:
        print(f"\nAvailable tools:")
        for tool in available_tools:
            priority = REQUIRED_TOOLS[tool].get('priority', 'medium')
            color = get_priority_color(priority)
            print(f"    - {tool} {color}[{priority.upper()}]{reset_color()}")
    
    if success:
        print(f"\n[+] Environment setup completed successfully!")
        print(f"[+] Framework is ready for operation.\n")
    else:
        print(f"\n[!] Environment setup completed with warnings!")
        print(f"[!] Framework may have limited functionality due to missing critical tools.\n")
    
    return success

if __name__ == "__main__":
    # Allow running env_setup.py standalone for testing
    if init_env():
        sys.exit(0)
    else:
        sys.exit(1)