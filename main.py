#!/usr/bin/env python3
"""
WireGuard Configuration Tester & Generator with Junk Packet Variations
Reads configs from directory, tests them, generates variations with different Jc/Jmin/Jmax

Supports: Linux and Windows
Requires: AmneziaWG or WireGuard with junk packet support

Usage:
Linux: sudo python3 wg_junk_tester.py --config-dir ./conf
Windows: python wg_junk_tester.py --config-dir .\conf (Run as Administrator)
"""

import os
import sys
import re
import json
import time
import shutil
import argparse
import platform
import subprocess
import statistics
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from copy import deepcopy
=============================================================================
CONFIGURATION CLASSES
=============================================================================

@dataclass
class JunkPacketParams:
"""Junk packet obfuscation parameters"""
Jc: int = 0 # Junk packet count
Jmin: int = 40 # Junk packet minimum size
Jmax: int = 70 # Junk packet maximum size
S1: int = 0 # Init packet junk size
S2: int = 0 # Response packet junk size
H1: int = 1 # Init packet magic header
H2: int = 2 # Response packet magic header
H3: int = 3 # Under load packet magic header
H4: int = 4 # Transport packet magic header

text

def to_dict(self) -> Dict[str, int]:
    return {
        'Jc': self.Jc, 'Jmin': self.Jmin, 'Jmax': self.Jmax,
        'S1': self.S1, 'S2': self.S2,
        'H1': self.H1, 'H2': self.H2, 'H3': self.H3, 'H4': self.H4
    }

def to_config_lines(self) -> List[str]:
    """Convert to config file lines"""
    lines = []
    if self.Jc > 0:
        lines.append(f"Jc = {self.Jc}")
        lines.append(f"Jmin = {self.Jmin}")
        lines.append(f"Jmax = {self.Jmax}")
    if self.S1 > 0:
        lines.append(f"S1 = {self.S1}")
    if self.S2 > 0:
        lines.append(f"S2 = {self.S2}")
    if self.H1 != 1:
        lines.append(f"H1 = {self.H1}")
    if self.H2 != 2:
        lines.append(f"H2 = {self.H2}")
    if self.H3 != 3:
        lines.append(f"H3 = {self.H3}")
    if self.H4 != 4:
        lines.append(f"H4 = {self.H4}")
    return lines

def describe(self) -> str:
    """Short description for naming"""
    return f"Jc{self.Jc}_Jmin{self.Jmin}_Jmax{self.Jmax}"

@dataclass
class WGConfig:
"""Parsed WireGuard configuration"""
name: str
filepath: str
interface_lines: List[str] = field(default_factory=list)
peer_lines: List[str] = field(default_factory=list)
junk_params: JunkPacketParams = field(default_factory=JunkPacketParams)
raw_content: str = ""

text

# Extracted values
private_key: str = ""
address: str = ""
dns: str = ""
mtu: int = 1420
endpoint: str = ""
public_key: str = ""
allowed_ips: str = ""
persistent_keepalive: int = 25

@dataclass
class TestResult:
"""Test result for a configuration"""
config_name: str
config_path: str
junk_params: Dict[str, int]
success: bool = False
handshake_ok: bool = False
handshake_time_ms: float = 0.0
ping_times: List[float] = field(default_factory=list)
ping_avg_ms: float = 0.0
ping_min_ms: float = 0.0
ping_max_ms: float = 0.0
packet_loss_pct: float = 100.0
errors: List[str] = field(default_factory=list)
timestamp: str = ""

text

def to_dict(self) -> Dict[str, Any]:
    return {
        'config_name': self.config_name,
        'config_path': self.config_path,
        'junk_params': self.junk_params,
        'success': self.success,
        'handshake_ok': self.handshake_ok,
        'handshake_time_ms': self.handshake_time_ms,
        'ping_avg_ms': self.ping_avg_ms,
        'ping_min_ms': self.ping_min_ms,
        'ping_max_ms': self.ping_max_ms,
        'packet_loss_pct': self.packet_loss_pct,
        'errors': self.errors,
        'timestamp': self.timestamp
    }

=============================================================================
CONFIG PARSER
=============================================================================

class ConfigParser:
"""Parse WireGuard configuration files"""

text

# Parameters that are junk packet related
JUNK_PARAMS = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']

@staticmethod
def parse_file(filepath: str) -> WGConfig:
    """Parse a WireGuard config file"""
    filepath = Path(filepath)
    config = WGConfig(
        name=filepath.stem,
        filepath=str(filepath)
    )

    with open(filepath, 'r', encoding='utf-8') as f:
        config.raw_content = f.read()

    lines = config.raw_content.split('\n')
    current_section = None

    for line in lines:
        line_stripped = line.strip()

        # Skip empty lines and comments
        if not line_stripped or line_stripped.startswith('#'):
            continue

        # Section headers
        if line_stripped.lower() == '[interface]':
            current_section = 'interface'
            continue
        elif line_stripped.lower() == '[peer]':
            current_section = 'peer'
            continue

        # Parse key = value
        if '=' in line_stripped:
            key, value = line_stripped.split('=', 1)
            key = key.strip()
            value = value.strip()

            # Check if it's a junk parameter
            if key in ConfigParser.JUNK_PARAMS:
                try:
                    setattr(config.junk_params, key, int(value))
                except ValueError:
                    pass
                continue

            # Store in appropriate section
            if current_section == 'interface':
                config.interface_lines.append(line_stripped)

                # Extract specific values
                if key.lower() == 'privatekey':
                    config.private_key = value
                elif key.lower() == 'address':
                    config.address = value
                elif key.lower() == 'dns':
                    config.dns = value
                elif key.lower() == 'mtu':
                    try:
                        config.mtu = int(value)
                    except:
                        pass

            elif current_section == 'peer':
                config.peer_lines.append(line_stripped)

                # Extract specific values
                if key.lower() == 'publickey':
                    config.public_key = value
                elif key.lower() == 'endpoint':
                    config.endpoint = value
                elif key.lower() == 'allowedips':
                    config.allowed_ips = value
                elif key.lower() == 'persistentkeepalive':
                    try:
                        config.persistent_keepalive = int(value)
                    except:
                        pass

    return config

@staticmethod
def parse_directory(dirpath: str) -> List[WGConfig]:
    """Parse all .conf files in a directory"""
    configs = []
    dirpath = Path(dirpath)

    if not dirpath.exists():
        print(f"Error: Directory '{dirpath}' does not exist!")
        return configs

    for conf_file in sorted(dirpath.glob('*.conf')):
        try:
            config = ConfigParser.parse_file(str(conf_file))
            configs.append(config)
            print(f"  Parsed: {conf_file.name}")
        except Exception as e:
            print(f"  Error parsing {conf_file.name}: {e}")

    return configs

=============================================================================
CONFIG GENERATOR
=============================================================================

class ConfigGenerator:
"""Generate new configs with different junk packet parameters"""

text

# Test variations for junk parameters
JUNK_COUNT_VALUES = [0, 1, 3, 5, 10, 15, 20, 30, 50]
JUNK_MIN_VALUES = [20, 40, 50, 64, 100, 150]
JUNK_MAX_VALUES = [70, 100, 150, 200, 300, 500, 1000]
S1_VALUES = [0, 50, 100, 150, 200]
S2_VALUES = [0, 50, 100, 150, 200]

def __init__(self, output_dir: str = "generated_configs"):
    self.output_dir = Path(output_dir)
    self.output_dir.mkdir(parents=True, exist_ok=True)

def generate_config_content(self, base_config: WGConfig, junk_params: JunkPacketParams) -> str:
    """Generate config file content with new junk parameters"""
    lines = []

    # Interface section
    lines.append("[Interface]")
    for line in base_config.interface_lines:
        lines.append(line)

    # Add junk parameters
    junk_lines = junk_params.to_config_lines()
    if junk_lines:
        lines.append("")  # Empty line before junk params
        lines.extend(junk_lines)

    # Peer section
    lines.append("")
    lines.append("[Peer]")
    for line in base_config.peer_lines:
        lines.append(line)

    return '\n'.join(lines)

def generate_variation(
    self,
    base_config: WGConfig,
    junk_params: JunkPacketParams,
    suffix: str = ""
) -> str:
    """Generate a single config variation and save to file"""

    content = self.generate_config_content(base_config, junk_params)

    # Generate filename
    if suffix:
        filename = f"{base_config.name}_{suffix}.conf"
    else:
        filename = f"{base_config.name}_{junk_params.describe()}.conf"

    filepath = self.output_dir / filename

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    # Set permissions on Linux
    if platform.system() != "Windows":
        os.chmod(filepath, 0o600)

    return str(filepath)

def generate_all_variations(self, base_config: WGConfig) -> List[Tuple[str, JunkPacketParams]]:
    """Generate all test variations for a base config"""
    variations = []

    print(f"\n  Generating variations for: {base_config.name}")

    # 1. Vary Junk Count with fixed min/max
    for jc in self.JUNK_COUNT_VALUES:
        params = JunkPacketParams(Jc=jc, Jmin=40, Jmax=70)
        filepath = self.generate_variation(base_config, params, f"jc{jc}")
        variations.append((filepath, params))

    # 2. Vary min/max sizes with fixed count
    for jmin in self.JUNK_MIN_VALUES:
        for jmax in self.JUNK_MAX_VALUES:
            if jmax > jmin:  # Max must be > min
                params = JunkPacketParams(Jc=5, Jmin=jmin, Jmax=jmax)
                filepath = self.generate_variation(
                    base_config, params,
                    f"jc5_min{jmin}_max{jmax}"
                )
                variations.append((filepath, params))

    # 3. Test S1/S2 handshake junk
    for s1 in self.S1_VALUES:
        for s2 in self.S2_VALUES:
            if s1 > 0 or s2 > 0:  # At least one non-zero
                params = JunkPacketParams(Jc=5, Jmin=40, Jmax=70, S1=s1, S2=s2)
                filepath = self.generate_variation(
                    base_config, params,
                    f"jc5_s1_{s1}_s2_{s2}"
                )
                variations.append((filepath, params))

    # 4. Aggressive obfuscation profiles
    aggressive_profiles = [
        ("aggressive_low", JunkPacketParams(Jc=10, Jmin=50, Jmax=200, S1=50, S2=50)),
        ("aggressive_med", JunkPacketParams(Jc=20, Jmin=100, Jmax=400, S1=100, S2=100)),
        ("aggressive_high", JunkPacketParams(Jc=40, Jmin=150, Jmax=800, S1=200, S2=200)),
        ("stealth", JunkPacketParams(Jc=3, Jmin=64, Jmax=128, S1=64, S2=64)),
    ]

    for name, params in aggressive_profiles:
        filepath = self.generate_variation(base_config, params, name)
        variations.append((filepath, params))

    print(f"    Generated {len(variations)} variations")
    return variations

def generate_custom_variation(
    self,
    base_config: WGConfig,
    jc: int,
    jmin: int,
    jmax: int,
    s1: int = 0,
    s2: int = 0
) -> Tuple[str, JunkPacketParams]:
    """Generate a single custom variation"""
    params = JunkPacketParams(Jc=jc, Jmin=jmin, Jmax=jmax, S1=s1, S2=s2)
    filepath = self.generate_variation(base_config, params)
    return filepath, params

=============================================================================
CONFIG TESTER
=============================================================================

class ConfigTester:
"""Test WireGuard configurations"""

text

def __init__(self, interface_name: str = "wg-test"):
    self.interface_name = interface_name
    self.system = platform.system()
    self.is_admin = self._check_admin()
    self.wg_cmd = self._find_wg_command()
    self.wg_quick_cmd = self._find_wg_quick_command()
    self.results: List[TestResult] = []

def _check_admin(self) -> bool:
    """Check for admin/root privileges"""
    if self.system == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return os.geteuid() == 0

def _find_wg_command(self) -> str:
    """Find WireGuard command"""
    if self.system == "Windows":
        candidates = [
            r"C:\Program Files\WireGuard\wg.exe",
            r"C:\Program Files\AmneziaWG\awg.exe",
            "wg", "awg"
        ]
    else:
        candidates = ["awg", "wg"]

    for cmd in candidates:
        try:
            if os.path.isfile(cmd) or shutil.which(cmd):
                return cmd
        except:
            pass
    return "wg"

def _find_wg_quick_command(self) -> str:
    """Find wg-quick command"""
    if self.system == "Windows":
        return "wireguard"

    for cmd in ["awg-quick", "wg-quick"]:
        if shutil.which(cmd):
            return cmd
    return "wg-quick"

def _run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)

def bring_up(self, config_path: str) -> Tuple[bool, float, str]:
    """Bring up WireGuard interface"""
    start_time = time.time()
    config_name = Path(config_path).stem

    try:
        if self.system == "Windows":
            # Remove existing tunnel
            self._run_command(
                ["wireguard", "/uninstalltunnelservice", config_name],
                timeout=10
            )
            time.sleep(1)

            # Install tunnel service
            code, out, err = self._run_command(
                ["wireguard", "/installtunnelservice", config_path],
                timeout=30
            )

            if code != 0:
                return False, 0, f"Install failed: {err}"

        else:
            # Linux - copy config to /etc/wireguard
            target_conf = f"/etc/wireguard/{self.interface_name}.conf"

            # Bring down if exists
            self._run_command([self.wg_quick_cmd, "down", self.interface_name], timeout=10)
            time.sleep(1)

            # Copy config
            shutil.copy(config_path, target_conf)
            os.chmod(target_conf, 0o600)

            # Bring up
            code, out, err = self._run_command(
                [self.wg_quick_cmd, "up", self.interface_name],
                timeout=30
            )

            if code != 0:
                return False, 0, f"Up failed: {err}"

        elapsed = (time.time() - start_time) * 1000
        time.sleep(2)  # Wait for handshake

        return True, elapsed, ""

    except Exception as e:
        return False, 0, str(e)

def bring_down(self, config_path: str = None):
    """Bring down WireGuard interface"""
    try:
        if self.system == "Windows":
            if config_path:
                config_name = Path(config_path).stem
                self._run_command(
                    ["wireguard", "/uninstalltunnelservice", config_name],
                    timeout=10
                )
        else:
            self._run_command(
                [self.wg_quick_cmd, "down", self.interface_name],
                timeout=10
            )
            # Cleanup
            target_conf = f"/etc/wireguard/{self.interface_name}.conf"
            if os.path.exists(target_conf):
                os.remove(target_conf)
    except:
        pass

def check_handshake(self) -> bool:
    """Check if handshake completed"""
    try:
        if self.system == "Windows":
            code, out, err = self._run_command([self.wg_cmd, "show"], timeout=5)
        else:
            code, out, err = self._run_command(
                [self.wg_cmd, "show", self.interface_name],
                timeout=5
            )
        return "latest handshake" in out.lower()
    except:
        return False

def run_ping_test(self, target: str = "1.1.1.1", count: int = 10) -> Tuple[List[float], float]:
    """Run ping test and return (ping_times, packet_loss_pct)"""
    try:
        if self.system == "Windows":
            cmd = ["ping", "-n", str(count), target]
        else:
            cmd = ["ping", "-c", str(count), "-W", "2", target]

        code, out, err = self._run_command(cmd, timeout=count * 3 + 10)

        # Parse ping times
        ping_times = []
        for line in out.split('\n'):
            if "time=" in line.lower():
                try:
                    # Extract time value
                    match = re.search(r'time[=<](\d+\.?\d*)', line.lower())
                    if match:
                        ping_times.append(float(match.group(1)))
                except:
                    pass

        # Calculate packet loss
        if ping_times:
            packet_loss = ((count - len(ping_times)) / count) * 100
        else:
            packet_loss = 100.0

        return ping_times, packet_loss

    except Exception as e:
        return [], 100.0

def test_config(
    self,
    config_path: str,
    junk_params: JunkPacketParams = None,
    ping_target: str = "1.1.1.1",
    ping_count: int = 10
) -> TestResult:
    """Test a single configuration"""

    config_name = Path(config_path).stem
    result = TestResult(
        config_name=config_name,
        config_path=config_path,
        junk_params=junk_params.to_dict() if junk_params else {},
        timestamp=datetime.now().isoformat()
    )

    print(f"\n  Testing: {config_name}")
    if junk_params:
        print(f"    Params: Jc={junk_params.Jc}, Jmin={junk_params.Jmin}, "
              f"Jmax={junk_params.Jmax}, S1={junk_params.S1}, S2={junk_params.S2}")

    # Bring up interface
    success, elapsed, error = self.bring_up(config_path)
    result.handshake_time_ms = elapsed

    if not success:
        result.errors.append(error)
        print(f"    ❌ Failed to connect: {error}")
        self.bring_down(config_path)
        self.results.append(result)
        return result

    result.success = True

    # Check handshake
    result.handshake_ok = self.check_handshake()
    if result.handshake_ok:
        print(f"    ✓ Handshake OK ({elapsed:.0f}ms)")
    else:
        print(f"    ⚠ No handshake detected")

    # Run ping test
    ping_times, packet_loss = self.run_ping_test(ping_target, ping_count)
    result.ping_times = ping_times
    result.packet_loss_pct = packet_loss

    if ping_times:
        result.ping_avg_ms = statistics.mean(ping_times)
        result.ping_min_ms = min(ping_times)
        result.ping_max_ms = max(ping_times)
        print(f"    ✓ Ping: avg={result.ping_avg_ms:.1f}ms, "
              f"min={result.ping_min_ms:.1f}ms, max={result.ping_max_ms:.1f}ms, "
              f"loss={packet_loss:.0f}%")
    else:
        print(f"    ❌ Ping failed (100% loss)")

    # Bring down interface
    self.bring_down(config_path)
    time.sleep(2)  # Cooldown between tests

    self.results.append(result)
    return result

def test_all(
    self,
    config_variations: List[Tuple[str, JunkPacketParams]],
    ping_target: str = "1.1.1.1",
    ping_count: int = 10
) -> List[TestResult]:
    """Test all configuration variations"""

    print(f"\n{'='*60}")
    print(f"TESTING {len(config_variations)} CONFIGURATIONS")
    print(f"{'='*60}")

    for i, (config_path, junk_params) in enumerate(config_variations, 1):
        print(f"\n[{i}/{len(config_variations)}]", end="")
        self.test_config(config_path, junk_params, ping_target, ping_count)

    return self.results

=============================================================================
RESULTS ANALYZER
=============================================================================

class ResultsAnalyzer:
"""Analyze and report test results"""

text

def __init__(self, results: List[TestResult]):
    self.results = results

def save_json(self, filepath: str):
    """Save results to JSON"""
    data = [r.to_dict() for r in self.results]
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print(f"\nResults saved to: {filepath}")

def save_csv(self, filepath: str):
    """Save results to CSV"""
    with open(filepath, 'w', encoding='utf-8') as f:
        # Header
        f.write("Config,Jc,Jmin,Jmax,S1,S2,Success,Handshake_OK,"
               "Handshake_ms,Ping_Avg_ms,Ping_Min_ms,Ping_Max_ms,Loss_Pct\n")

        for r in self.results:
            jp = r.junk_params
            f.write(f"{r.config_name},{jp.get('Jc',0)},{jp.get('Jmin',0)},"
                   f"{jp.get('Jmax',0)},{jp.get('S1',0)},{jp.get('S2',0)},"
                   f"{r.success},{r.handshake_ok},{r.handshake_time_ms:.1f},"
                   f"{r.ping_avg_ms:.1f},{r.ping_min_ms:.1f},{r.ping_max_ms:.1f},"
                   f"{r.packet_loss_pct:.1f}\n")

    print(f"CSV saved to: {filepath}")

def print_summary(self):
    """Print results summary"""
    print(f"\n{'='*70}")
    print("TEST RESULTS SUMMARY")
    print(f"{'='*70}")

    successful = [r for r in self.results if r.success and r.handshake_ok]
    failed = [r for r in self.results if not r.success or not r.handshake_ok]

    print(f"\nTotal: {len(self.results)} | "
          f"Success: {len(successful)} | Failed: {len(failed)}")

    if successful:
        print(f"\n{'─'*70}")
        print(f"{'Config':<30} {'Jc':<5} {'Min':<5} {'Max':<5} "
              f"{'Ping(ms)':<10} {'Loss%':<8}")
        print(f"{'─'*70}")

        # Sort by ping avg
        for r in sorted(successful, key=lambda x: x.ping_avg_ms if x.ping_avg_ms > 0 else 9999):
            jp = r.junk_params
            name = r.config_name[:28]
            print(f"{name:<30} {jp.get('Jc',0):<5} {jp.get('Jmin',0):<5} "
                  f"{jp.get('Jmax',0):<5} {r.ping_avg_ms:<10.1f} {r.packet_loss_pct:<8.1f}")

    # Best configuration
    if successful:
        best = min(successful, key=lambda x: x.ping_avg_ms if x.ping_avg_ms > 0 else 9999)
        print(f"\n{'─'*70}")
        print(f"🏆 BEST CONFIGURATION: {best.config_name}")
        print(f"   Jc={best.junk_params.get('Jc',0)}, "
              f"Jmin={best.junk_params.get('Jmin',0)}, "
              f"Jmax={best.junk_params.get('Jmax',0)}")
        print(f"   Ping: {best.ping_avg_ms:.1f}ms avg, {best.packet_loss_pct:.1f}% loss")

    # Failed configs
    if failed:
        print(f"\n{'─'*70}")
        print("FAILED CONFIGURATIONS:")
        for r in failed[:10]:  # Show first 10
            print(f"  ❌ {r.config_name}: {', '.join(r.errors) if r.errors else 'No handshake'}")

def get_best_params(self) -> Optional[JunkPacketParams]:
    """Get the best performing junk parameters"""
    successful = [r for r in self.results if r.success and r.handshake_ok and r.ping_avg_ms > 0]
    if not successful:
        return None

    best = min(successful, key=lambda x: x.ping_avg_ms)
    jp = best.junk_params

    return JunkPacketParams(
        Jc=jp.get('Jc', 0),
        Jmin=jp.get('Jmin', 40),
        Jmax=jp.get('Jmax', 70),
        S1=jp.get('S1', 0),
        S2=jp.get('S2', 0)
    )

=============================================================================
MAIN APPLICATION
=============================================================================

class WGJunkTester:
"""Main application class"""

text

def __init__(self, config_dir: str, output_dir: str = "output"):
    self.config_dir = Path(config_dir)
    self.output_dir = Path(output_dir)
    self.output_dir.mkdir(parents=True, exist_ok=True)

    self.generated_dir = self.output_dir / "generated_configs"
    self.results_dir = self.output_dir / "results"
    self.results_dir.mkdir(parents=True, exist_ok=True)

    self.base_configs: List[WGConfig] = []
    self.variations: List[Tuple[str, JunkPacketParams]] = []
    self.results: List[TestResult] = []

def load_configs(self) -> int:
    """Load configurations from config directory"""
    print(f"\n{'='*60}")
    print(f"LOADING CONFIGURATIONS FROM: {self.config_dir}")
    print(f"{'='*60}")

    self.base_configs = ConfigParser.parse_directory(str(self.config_dir))

    print(f"\nLoaded {len(self.base_configs)} configurations")

    for config in self.base_configs:
        print(f"\n  📄 {config.name}")
        print(f"     Endpoint: {config.endpoint}")
        print(f"     Current Junk: Jc={config.junk_params.Jc}, "
              f"Jmin={config.junk_params.Jmin}, Jmax={config.junk_params.Jmax}")

    return len(self.base_configs)

def generate_variations(self, custom_only: bool = False,
                       jc: int = None, jmin: int = None, jmax: int = None) -> int:
    """Generate configuration variations"""
    print(f"\n{'='*60}")
    print("GENERATING CONFIGURATION VARIATIONS")
    print(f"{'='*60}")

    generator = ConfigGenerator(str(self.generated_dir))
    self.variations = []

    for base_config in self.base_configs:
        if custom_only and jc is not None:
            # Generate single custom variation
            filepath, params = generator.generate_custom_variation(
                base_config,
                jc=jc,
                jmin=jmin or 40,
                jmax=jmax or 70
            )
            self.variations.append((filepath, params))
            print(f"  Generated custom: {Path(filepath).name}")
        else:
            # Generate all variations
            variations = generator.generate_all_variations(base_config)
            self.variations.extend(variations)

    print(f"\nGenerated {len(self.variations)} total variations")
    return len(self.variations)

def run_tests(self, ping_target: str = "1.1.1.1", ping_count: int = 10) -> int:
    """Run tests on all variations"""
    tester = ConfigTester()

    if not tester.is_admin:
        print("\n❌ ERROR: Administrator/root privileges required!")
        print("   Linux: sudo python3 wg_junk_tester.py ...")
        print("   Windows: Run as Administrator")
        return 0

    # Also test original configs
    original_variations = []
    for config in self.base_configs:
        original_variations.append((config.filepath, config.junk_params))

    all_variations = original_variations + self.variations

    self.results = tester.test_all(all_variations, ping_target, ping_count)
    return len(self.results)

def analyze_and_save(self):
    """Analyze results and save reports"""
    if not self.results:
        print("\nNo results to analyze")
        return

    analyzer = ResultsAnalyzer(self.results)

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    analyzer.save_json(str(self.results_dir / f"results_{timestamp}.json"))
    analyzer.save_csv(str(self.results_dir / f"results_{timestamp}.csv"))

    # Print summary
    analyzer.print_summary()

    # Get best params and generate recommended config
    best_params = analyzer.get_best_params()
    if best_params and self.base_configs:
        print(f"\n{'='*60}")
        print("RECOMMENDED CONFIGURATION")
        print(f"{'='*60}")

        generator = ConfigGenerator(str(self.output_dir))
        for base_config in self.base_configs:
            filepath = generator.generate_variation(
                base_config,
                best_params,
                "RECOMMENDED"
            )
            print(f"\n  📄 {filepath}")
            print(f"\n  Content:")
            with open(filepath, 'r') as f:
                print(f"  {'-'*40}")
                for line in f:
                    print(f"  {line.rstrip()}")
                print(f"  {'-'*40}")

def main():
parser = argparse.ArgumentParser(
description="WireGuard Configuration Tester with Junk Packet Variations",
formatter_class=argparse.RawDescriptionHelpFormatter,
epilog="""
Examples:
Test all variations of configs in ./conf directory

sudo python3 wg_junk_tester.py --config-dir ./conf
Generate and test only, no actual connection tests

python3 wg_junk_tester.py --config-dir ./conf --generate-only
Test specific junk parameters

sudo python3 wg_junk_tester.py --config-dir ./conf --jc 10 --jmin 50 --jmax 200
Custom ping target and count

sudo python3 wg_junk_tester.py --config-dir ./conf --ping-target 8.8.8.8 --ping-count 20
"""
)

text

parser.add_argument('--config-dir', '-c', default='conf',
                   help='Directory containing WireGuard .conf files (default: conf)')
parser.add_argument('--output-dir', '-o', default='output',
                   help='Output directory for generated configs and results (default: output)')
parser.add_argument('--ping-target', default='1.1.1.1',
                   help='IP address to ping for connectivity test (default: 1.1.1.1)')
parser.add_argument('--ping-count', type=int, default=10,
                   help='Number of pings per test (default: 10)')
parser.add_argument('--generate-only', action='store_true',
                   help='Only generate configs, do not test')
parser.add_argument('--test-original', action='store_true',
                   help='Only test original configs without generating variations')

# Custom junk parameters
parser.add_argument('--jc', type=int, help='Custom Junk packet count')
parser.add_argument('--jmin', type=int, help='Custom Junk packet min size')
parser.add_argument('--jmax', type=int, help='Custom Junk packet max size')
parser.add_argument('--s1', type=int, default=0, help='Custom S1 (init junk size)')
parser.add_argument('--s2', type=int, default=0, help='Custom S2 (response junk size)')

args = parser.parse_args()

# Print header
print("""

╔══════════════════════════════════════════════════════════════╗
║ WireGuard Junk Packet Configuration Tester ║
║ Supports: AmneziaWG / WireGuard with obfuscation ║
╚══════════════════════════════════════════════════════════════╝
""")
print(f"Platform: {platform.system()} {platform.release()}")
print(f"Config Directory: {args.config_dir}")
print(f"Output Directory: {args.output_dir}")

text

# Create main application
app = WGJunkTester(args.config_dir, args.output_dir)

# Load configs
if app.load_configs() == 0:
    print("\n❌ No configurations found!")
    print(f"   Please place .conf files in: {args.config_dir}")
    sys.exit(1)

# Test original only
if args.test_original:
    app.run_tests(args.ping_target, args.ping_count)
    app.analyze_and_save()
    sys.exit(0)

# Generate variations
custom_only = args.jc is not None
app.generate_variations(
    custom_only=custom_only,
    jc=args.jc,
    jmin=args.jmin,
    jmax=args.jmax
)

if args.generate_only:
    print("\n✓ Configurations generated (--generate-only specified)")
    print(f"  Output: {app.generated_dir}")
    sys.exit(0)

# Run tests
app.run_tests(args.ping_target, args.ping_count)

# Analyze and save
app.analyze_and_save()

print(f"\n{'='*60}")
print("COMPLETE!")
print(f"{'='*60}")
print(f"Results saved in: {app.results_dir}")
print(f"Generated configs in: {app.generated_dir}")

if name == "main":
main()
