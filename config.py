import os
import json
import tempfile
from datetime import datetime

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
STATE_FILE = os.path.join(DATA_DIR, 'state.json')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
LOGS_FILE = os.path.join(LOGS_DIR, 'env_info.txt')

# Legacy directories (keeping for scan outputs)
SCOPE_DIR = os.path.join(DATA_DIR, 'scope')
ALIVE_DIR = os.path.join(DATA_DIR, 'alive')
SCAN_OUTPUT_DIR = os.path.join(ALIVE_DIR, 'scan_output')

# Define scope directories (keeping for backward compatibility)
USER_SCOPE_DIR = os.path.join(SCOPE_DIR, 'user_scope')
NORMALIZED_SCOPE_DIR = os.path.join(SCOPE_DIR, 'normalized_scope')

# Port Directories
OPEN_PORT_DIR = os.path.join(DATA_DIR, 'open_port')
COMMON_PORT_DIR = os.path.join(OPEN_PORT_DIR, 'common_port')
FULL_PORT_DIR = os.path.join(OPEN_PORT_DIR, 'full_port')
COMMON_PORT_PN_DIR = os.path.join(OPEN_PORT_DIR, 'common_port_pn')
FULL_PORT_PN_DIR = os.path.join(OPEN_PORT_DIR, 'full_port_pn')

# Ensure directories exist
for directory in [
    DATA_DIR,
    LOGS_DIR,
    SCOPE_DIR,
    ALIVE_DIR,
    SCAN_OUTPUT_DIR,
    USER_SCOPE_DIR,
    NORMALIZED_SCOPE_DIR,
    OPEN_PORT_DIR,
    COMMON_PORT_DIR,
    FULL_PORT_DIR,
    COMMON_PORT_PN_DIR
]:
    os.makedirs(directory, exist_ok=True)

def get_timestamp():
    """Return current timestamp in standardized format"""
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def load_state():
    """Load state from JSON file with error handling"""
    if not os.path.exists(STATE_FILE):
        return init_empty_state()
    
    try:
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load state file ({e}). Creating new state.")
        return init_empty_state()

def save_state(state_data):
    """Atomically save state to JSON file"""
    try:
        # Create temporary file in the same directory as the target
        temp_fd, temp_path = tempfile.mkstemp(
            dir=DATA_DIR, 
            prefix='state_', 
            suffix='.tmp'
        )
        
        with os.fdopen(temp_fd, 'w') as temp_file:
            json.dump(state_data, temp_file, indent=2)
        
        # Atomically replace the original file
        if os.name == 'nt':  # Windows
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
            os.rename(temp_path, STATE_FILE)
        else:  # Unix-like systems
            os.rename(temp_path, STATE_FILE)
        
        return True
    except Exception as e:
        print(f"Error saving state: {e}")
        # Clean up temp file if it exists
        try:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass
        return False

def init_empty_state():
    """Initialize empty state structure"""
    return {
        "metadata": {
            "created": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "version": "1.0"
        },
        "scope": {
            "raw_entries": [],
            "normalized_entries": [],
            "total_targets": 0,
            "timestamp": None
        },
        "hosts": {},
        "scans": {
            "alive_detection": {
                "completed": False,
                "timestamp": None,
                "methods_used": [],
                "total_alive": 0
            },
            "port_scanning": {
                "completed": False,
                "timestamp": None,
                "ports_scanned": [],
                "total_open_ports": 0
            }
        },
        "statistics": {
            "total_targets": 0,
            "alive_hosts": 0,
            "total_open_ports": 0,
            "services_identified": 0
        }
    }

def update_state_metadata(state):
    """Update metadata timestamps"""
    state["metadata"]["last_updated"] = datetime.now().isoformat()
    return state