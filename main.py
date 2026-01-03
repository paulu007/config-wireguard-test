#!/usr/bin/env python3
"""
AmneziaWG Configuration Tester - FIXED VERSION
Properly detects and requires AmneziaWG (not standard WireGuard)
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
from itertools import product


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AWGParams:
    """AmneziaWG obfuscation parameters"""
    Jc: int = 0
    Jmin: int = 40
    Jmax: int = 70
    S1: int = 0
    S2: int = 0
    H1: int = 1
    H2: int = 2
    H3: int = 3
    H4: int = 4

    def to_dict(self) -> Dict[str, int]:
        return vars(self).copy()

    def to_config_lines(self) -> List[str]:
        return [
            f"Jc = {self.Jc}",
            f"Jmin = {self.Jmin}",
            f"Jmax = {self.Jmax}",
            f"S1 = {self.S1}",
            f"S2 = {self.S2}",
            f"H1 = {self.H1}",
            f"H2 = {self.H2}",
            f"H3 = {self.H3}",
            f"H4 = {self.H4}",
        ]

    def short_name(self) -> str:
        return f"Jc{self.Jc}_Jmin{self.Jmin}_Jmax{self.Jmax}_S1{self.S1}_S2{self.S2}"

    def copy(self, **kwargs) -> 'AWGParams':
        params = AWGParams(**vars(self))
        for key, value in kwargs.items():
            if hasattr(params, key):
                setattr(params, key, value)
        return params


@dataclass
class WGConfig:
    """Parsed WireGuard configuration"""
    name: str
    filepath: str
    interface_lines: List[str] = field(default_factory=list)
    peer_lines: List[str] = field(default_factory=list)
    params: AWGParams = field(default_factory=AWGParams)
    private_key: str = ""
    address: str = ""
    dns: str = ""
    endpoint: str = ""
    public_key: str = ""


@dataclass
class TestResult:
    """Test result"""
    config_name: str
    params: Dict[str, int]
    success: bool = False
    handshake_ok: bool = False
    ping_avg_ms: float = 0.0
    ping_min_ms: float = 0.0
    ping_max_ms: float = 0.0
    packet_loss: float = 100.0
    error: str = ""
    timestamp: str = ""


# =============================================================================
# CONFIG PARSER
# =============================================================================

class ConfigParser:
    """Parse WireGuard/AmneziaWG configuration files"""
    
    AWG_PARAMS = {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'}

    @classmethod
    def parse(cls, filepath: str) -> WGConfig:
        path = Path(filepath)
        config = WGConfig(name=path.stem, filepath=str(path))
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        section = None
        for line in content.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.lower() == '[interface]':
                section = 'interface'
                continue
            elif line.lower() == '[peer]':
                section = 'peer'
                continue
            
            if '=' not in line:
                continue
                
            key, value = [x.strip() for x in line.split('=', 1)]
            
            if key in cls.AWG_PARAMS:
                try:
                    setattr(config.params, key, int(value))
                except ValueError:
                    pass
                continue
            
            if section == 'interface':
                config.interface_lines.append(line)
                key_lower = key.lower()
                if key_lower == 'privatekey':
                    config.private_key = value
                elif key_lower == 'address':
                    config.address = value
                elif key_lower == 'dns':
                    config.dns = value
                    
            elif section == 'peer':
                config.peer_lines.append(line)
                key_lower = key.lower()
                if key_lower == 'publickey':
                    config.public_key = value
                elif key_lower == 'endpoint':
                    config.endpoint = value
        
        return config

    @classmethod
    def parse_directory(cls, dirpath: str) -> List[WGConfig]:
        configs = []
        path = Path(dirpath)
        
        if not path.exists():
            print(f"❌ Directory not found: {dirpath}")
            return configs
        
        for conf_file in sorted(path.glob('*.conf')):
            try:
                config = cls.parse(str(conf_file))
                configs.append(config)
                print(f"  ✓ {conf_file.name}")
                p = config.params
                print(f"    Jc={p.Jc}, Jmin={p.Jmin}, Jmax={p.Jmax}, "
                      f"S1={p.S1}, S2={p.S2}")
                print(f"    H1={p.H1}, H2={p.H2}, H3={p.H3}, H4={p.H4}")
            except Exception as e:
                print(f"  ✗ {conf_file.name}: {e}")
        
        return configs


# =============================================================================
# CONFIG GENERATOR
# =============================================================================

class ConfigGenerator:
    """Generate config variations"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, base_config: WGConfig, params: AWGParams, suffix: str = "") -> str:
        lines = ["[Interface]"]
        lines.extend(base_config.interface_lines)
        lines.append("")
        lines.extend(params.to_config_lines())
        lines.append("")
        lines.append("[Peer]")
        lines.extend(base_config.peer_lines)
        
        if suffix:
            filename = f"{base_config.name}_{suffix}.conf"
        else:
            filename = f"{base_config.name}_{params.short_name()}.conf"
        
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        if platform.system() != "Windows":
            os.chmod(filepath, 0o600)
        
        return str(filepath)
    
    def generate_variations(
        self,
        base_config: WGConfig,
        jc_values: List[int],
        jmin_values: List[int],
        jmax_values: List[int],
        s1_values: List[int],
        s2_values: List[int],
        h1: int, h2: int, h3: int, h4: int
    ) -> List[Tuple[str, AWGParams]]:
        variations = []
        
        for jc, jmin, jmax, s1, s2 in product(
            jc_values, jmin_values, jmax_values, s1_values, s2_values
        ):
            if jmax <= jmin:
                continue
            
            params = AWGParams(
                Jc=jc, Jmin=jmin, Jmax=jmax,
                S1=s1, S2=s2,
                H1=h1, H2=h2, H3=h3, H4=h4
            )
            
            filepath = self.generate(base_config, params)
            variations.append((filepath, params))
        
        return variations


# =============================================================================
# AMNEZIAWG DETECTOR
# =============================================================================

class AWGDetector:
    """Detect and validate AmneziaWG installation"""
    
    def __init__(self):
        self.system = platform.system()
        self.awg_quick = None
        self.awg_show = None
        self.is_awg = False
        
        self._detect()
    
    def _detect(self):
        """Detect AmneziaWG tools"""
        if self.system == "Windows":
            self._detect_windows()
        else:
            self._detect_linux()
    
    def _detect_linux(self):
        """Detect on Linux"""
        # Check for awg-quick (AmneziaWG)
        awg_quick = shutil.which("awg-quick")
        if awg_quick:
            self.awg_quick = awg_quick
            self.is_awg = True
        else:
            # Fallback to wg-quick (will fail with AWG params!)
            wg_quick = shutil.which("wg-quick")
            if wg_quick:
                self.awg_quick = wg_quick
                self.is_awg = False
        
        # Check for awg show command
        awg = shutil.which("awg")
        if awg:
            self.awg_show = awg
        else:
            wg = shutil.which("wg")
            if wg:
                self.awg_show = wg
    
    def _detect_windows(self):
        """Detect on Windows"""
        # Check for AmneziaWG
        awg_paths = [
            r"C:\Program Files\AmneziaWG\awg.exe",
            r"C:\Program Files (x86)\AmneziaWG\awg.exe",
        ]
        
        for path in awg_paths:
            if os.path.exists(path):
                self.awg_show = path
                self.awg_quick = "wireguard"  # Windows uses wireguard.exe for tunnel service
                self.is_awg = True
                return
        
        # Fallback to standard WireGuard
        wg_paths = [
            r"C:\Program Files\WireGuard\wg.exe",
            r"C:\Program Files (x86)\WireGuard\wg.exe",
        ]
        
        for path in wg_paths:
            if os.path.exists(path):
                self.awg_show = path
                self.awg_quick = "wireguard"
                self.is_awg = False
                return
    
    def check(self) -> bool:
        """Check if AmneziaWG is available and print status"""
        print(f"\n{'='*60}")
        print("CHECKING AMNEZIAWG INSTALLATION")
        print(f"{'='*60}")
        
        if self.awg_quick:
            print(f"  awg-quick/wg-quick: {self.awg_quick}")
        else:
            print(f"  ❌ awg-quick/wg-quick: NOT FOUND")
        
        if self.awg_show:
            print(f"  awg/wg command: {self.awg_show}")
        else:
            print(f"  ❌ awg/wg command: NOT FOUND")
        
        if self.is_awg:
            print(f"\n  ✓ AmneziaWG detected - obfuscation parameters supported")
            return True
        else:
            print(f"\n  ⚠️  WARNING: Only standard WireGuard found!")
            print(f"  ⚠️  Obfuscation parameters (Jc, Jmin, Jmax, S1, S2, H1-H4)")
            print(f"  ⚠️  will NOT work with standard WireGuard!")
            print(f"\n  Please install AmneziaWG:")
            print(f"    Ubuntu/Debian:")
            print(f"      sudo add-apt-repository ppa:amnezia/ppa")
            print(f"      sudo apt update")
            print(f"      sudo apt install amneziawg amneziawg-tools")
            print(f"\n    Or build from source:")
            print(f"      https://github.com/amnezia-vpn/amneziawg-tools")
            return False
    
    def verify_awg_works(self) -> bool:
        """Verify AWG actually supports obfuscation"""
        if not self.awg_show:
            return False
        
        try:
            result = subprocess.run(
                [self.awg_show, "--help"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # AWG should show in help or version
            output = result.stdout + result.stderr
            return "amnezia" in output.lower() or self.is_awg
        except:
            return self.is_awg


# =============================================================================
# CONFIG TESTER
# =============================================================================

class ConfigTester:
    """Test WireGuard configurations"""
    
    def __init__(self, interface: str = "awg-test", detector: AWGDetector = None):
        self.interface = interface
        self.system = platform.system()
        self.detector = detector or AWGDetector()
        self.is_admin = self._check_admin()
        
        self.awg_quick = self.detector.awg_quick
        self.awg_show = self.detector.awg_show
    
    def _check_admin(self) -> bool:
        if self.system == "Windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        return os.geteuid() == 0
    
    def _run(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout"
        except Exception as e:
            return -1, "", str(e)
    
    def _up(self, config_path: str) -> Tuple[bool, str]:
        """Bring up interface"""
        config_name = Path(config_path).stem
        
        try:
            if self.system == "Windows":
                # Windows with AmneziaWG
                self._run(["wireguard", "/uninstalltunnelservice", config_name], 10)
                time.sleep(1)
                
                # For AmneziaWG on Windows, use the AmneziaWG service
                if self.detector.is_awg:
                    code, out, err = self._run(
                        ["wireguard", "/installtunnelservice", config_path], 30
                    )
                else:
                    code, out, err = self._run(
                        ["wireguard", "/installtunnelservice", config_path], 30
                    )
                
                if code != 0:
                    return False, f"Install failed: {err}"
            else:
                # Linux
                # Bring down existing
                self._run([self.awg_quick, "down", self.interface], 10)
                time.sleep(1)
                
                # Copy config to /etc/wireguard (or /etc/amnezia/amneziawg)
                if self.detector.is_awg:
                    # Try AmneziaWG config directory first
                    target_dirs = [
                        f"/etc/amnezia/amneziawg/{self.interface}.conf",
                        f"/etc/wireguard/{self.interface}.conf"
                    ]
                else:
                    target_dirs = [f"/etc/wireguard/{self.interface}.conf"]
                
                target = target_dirs[0]
                
                # Create directory if needed
                os.makedirs(os.path.dirname(target), exist_ok=True)
                
                shutil.copy(config_path, target)
                os.chmod(target, 0o600)
                
                # Bring up
                code, out, err = self._run([self.awg_quick, "up", self.interface], 30)
                
                if code != 0:
                    # Full error output for debugging
                    full_error = f"{out}\n{err}".strip()
                    return False, full_error
            
            time.sleep(3)  # Wait for handshake
            return True, ""
            
        except Exception as e:
            return False, str(e)
    
    def _down(self, config_path: str = None):
        """Bring down interface"""
        try:
            if self.system == "Windows" and config_path:
                config_name = Path(config_path).stem
                self._run(["wireguard", "/uninstalltunnelservice", config_name], 10)
            else:
                self._run([self.awg_quick, "down", self.interface], 10)
                
                # Cleanup config files
                for target in [
                    f"/etc/wireguard/{self.interface}.conf",
                    f"/etc/amnezia/amneziawg/{self.interface}.conf"
                ]:
                    if os.path.exists(target):
                        os.remove(target)
        except:
            pass
    
    def _check_handshake(self) -> bool:
        """Check if handshake completed"""
        try:
            if self.system == "Windows":
                code, out, _ = self._run([self.awg_show, "show"], 5)
            else:
                code, out, _ = self._run([self.awg_show, "show", self.interface], 5)
            return "latest handshake" in out.lower()
        except:
            return False
    
    def _ping_test(self, target: str, count: int) -> Tuple[List[float], float]:
        """Run ping test"""
        try:
            if self.system == "Windows":
                cmd = ["ping", "-n", str(count), target]
            else:
                cmd = ["ping", "-c", str(count), "-W", "2", target]
            
            code, out, _ = self._run(cmd, count * 3 + 10)
            
            times = []
            for line in out.split('\n'):
                match = re.search(r'time[=<](\d+\.?\d*)', line.lower())
                if match:
                    times.append(float(match.group(1)))
            
            loss = ((count - len(times)) / count) * 100 if count > 0 else 100
            return times, loss
            
        except:
            return [], 100.0
    
    def test(
        self,
        config_path: str,
        params: AWGParams,
        ping_target: str = "1.1.1.1",
        ping_count: int = 5
    ) -> TestResult:
        """Test a single configuration"""
        
        result = TestResult(
            config_name=Path(config_path).stem,
            params=params.to_dict(),
            timestamp=datetime.now().isoformat()
        )
        
        success, error = self._up(config_path)
        if not success:
            result.error = error
            self._down(config_path)
            return result
        
        result.success = True
        result.handshake_ok = self._check_handshake()
        
        if result.handshake_ok:
            times, loss = self._ping_test(ping_target, ping_count)
            result.packet_loss = loss
            if times:
                result.ping_avg_ms = statistics.mean(times)
                result.ping_min_ms = min(times)
                result.ping_max_ms = max(times)
        
        self._down(config_path)
        time.sleep(2)
        
        return result


# =============================================================================
# MAIN TESTER APPLICATION
# =============================================================================

class AWGTester:
    """Main application"""
    
    def __init__(self, args):
        self.args = args
        self.config_dir = Path(args.config_dir)
        self.output_dir = Path(args.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.generated_dir = self.output_dir / "generated"
        self.results_dir = self.output_dir / "results"
        self.generated_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        
        self.configs: List[WGConfig] = []
        self.variations: List[Tuple[str, AWGParams]] = []
        self.results: List[TestResult] = []
        
        # Detector
        self.detector = AWGDetector()
        
        # Parse parameter values
        self.jc_values = self._parse_values(args.jc_values, args.jc_range, [0, 3, 5, 10])
        self.jmin_values = self._parse_values(args.jmin_values, args.jmin_range, [40, 50])
        self.jmax_values = self._parse_values(args.jmax_values, args.jmax_range, [70, 100, 150])
        self.s1_values = self._parse_values(args.s1_values, args.s1_range, [0, 50])
        self.s2_values = self._parse_values(args.s2_values, args.s2_range, [0, 50])
        
        # H1-H4 values
        self.h1 = args.h1
        self.h2 = args.h2
        self.h3 = args.h3
        self.h4 = args.h4
    
    def _parse_values(
        self,
        values_str: Optional[str],
        range_args: Optional[List[int]],
        default: List[int]
    ) -> List[int]:
        if values_str:
            return [int(x.strip()) for x in values_str.split(',')]
        if range_args:
            start, end, step = range_args
            return list(range(start, end + 1, step))
        return default
    
    def check_environment(self) -> bool:
        """Check if environment is ready"""
        if not self.detector.check():
            if not self.args.generate_only and not self.args.force:
                print(f"\n❌ Cannot proceed without AmneziaWG for testing.")
                print(f"   Use --generate-only to just generate configs")
                print(f"   Use --force to try anyway (will likely fail)")
                return False
        return True
    
    def load_configs(self) -> int:
        print(f"\n{'='*60}")
        print(f"LOADING CONFIGS FROM: {self.config_dir}")
        print(f"{'='*60}\n")
        
        self.configs = ConfigParser.parse_directory(str(self.config_dir))
        print(f"\nLoaded: {len(self.configs)} configurations")
        return len(self.configs)
    
    def generate_variations(self) -> int:
        print(f"\n{'='*60}")
        print("GENERATING VARIATIONS")
        print(f"{'='*60}")
        print(f"\nParameters to test:")
        print(f"  Jc:   {self.jc_values}")
        print(f"  Jmin: {self.jmin_values}")
        print(f"  Jmax: {self.jmax_values}")
        print(f"  S1:   {self.s1_values}")
        print(f"  S2:   {self.s2_values}")
        print(f"\nFixed headers:")
        print(f"  H1={self.h1}, H2={self.h2}, H3={self.h3}, H4={self.h4}")
        
        generator = ConfigGenerator(str(self.generated_dir))
        self.variations = []
        
        for config in self.configs:
            print(f"\n  Generating for: {config.name}")
            
            variations = generator.generate_variations(
                config,
                self.jc_values,
                self.jmin_values,
                self.jmax_values,
                self.s1_values,
                self.s2_values,
                self.h1, self.h2, self.h3, self.h4
            )
            
            self.variations.extend(variations)
            print(f"    Created {len(variations)} variations")
        
        print(f"\nTotal variations: {len(self.variations)}")
        return len(self.variations)
    
    def run_tests(self) -> int:
        tester = ConfigTester(detector=self.detector)
        
        if not tester.is_admin:
            print("\n❌ Administrator/root privileges required!")
            print("   Linux:   sudo python3 awg_tester.py ...")
            print("   Windows: Run as Administrator")
            return 0
        
        print(f"\n{'='*60}")
        print(f"TESTING {len(self.variations)} CONFIGURATIONS")
        print(f"{'='*60}")
        print(f"\nUsing: {self.detector.awg_quick}")
        print(f"Is AmneziaWG: {self.detector.is_awg}")
        
        for i, (config_path, params) in enumerate(self.variations, 1):
            name = Path(config_path).stem
            print(f"\n[{i}/{len(self.variations)}] {name}")
            print(f"  Jc={params.Jc}, Jmin={params.Jmin}, Jmax={params.Jmax}, "
                  f"S1={params.S1}, S2={params.S2}")
            
            result = tester.test(
                config_path, params,
                self.args.ping_target,
                self.args.ping_count
            )
            self.results.append(result)
            
            if result.handshake_ok:
                print(f"  ✓ Handshake OK | Ping: {result.ping_avg_ms:.1f}ms | "
                      f"Loss: {result.packet_loss:.0f}%")
            elif result.success:
                print(f"  ⚠ Connected but no handshake")
            else:
                # Truncate long errors
                error_short = result.error[:100] + "..." if len(result.error) > 100 else result.error
                print(f"  ✗ Failed: {error_short}")
                
                # Check for the specific AWG error
                if "Line unrecognized" in result.error or "Jc" in result.error:
                    print(f"  ⚠ This error means standard WireGuard is being used!")
                    print(f"  ⚠ Please install AmneziaWG (awg-quick, awg)")
                    if not self.args.force:
                        print(f"\n  Stopping tests. Use --force to continue anyway.")
                        break
        
        return len(self.results)
    
    def save_results(self):
        if not self.results:
            print("\nNo results to save")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON
        json_path = self.results_dir / f"results_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump([{
                'name': r.config_name,
                'params': r.params,
                'success': r.success,
                'handshake': r.handshake_ok,
                'ping_avg': r.ping_avg_ms,
                'ping_min': r.ping_min_ms,
                'ping_max': r.ping_max_ms,
                'loss': r.packet_loss,
                'error': r.error
            } for r in self.results], f, indent=2)
        
        # CSV
        csv_path = self.results_dir / f"results_{timestamp}.csv"
        with open(csv_path, 'w') as f:
            f.write("Config,Jc,Jmin,Jmax,S1,S2,H1,H2,H3,H4,"
                   "Success,Handshake,Ping_Avg,Ping_Min,Ping_Max,Loss,Error\n")
            for r in self.results:
                p = r.params
                error_clean = r.error.replace(',', ';').replace('\n', ' ')[:50]
                f.write(f"{r.config_name},{p['Jc']},{p['Jmin']},{p['Jmax']},"
                       f"{p['S1']},{p['S2']},{p['H1']},{p['H2']},{p['H3']},{p['H4']},"
                       f"{r.success},{r.handshake_ok},{r.ping_avg_ms:.1f},"
                       f"{r.ping_min_ms:.1f},{r.ping_max_ms:.1f},{r.packet_loss:.1f},"
                       f"\"{error_clean}\"\n")
        
        print(f"\n{'='*60}")
        print("RESULTS SAVED")
        print(f"{'='*60}")
        print(f"  JSON: {json_path}")
        print(f"  CSV:  {csv_path}")
        
        self._print_summary()
    
    def _print_summary(self):
        print(f"\n{'='*70}")
        print("SUMMARY")
        print(f"{'='*70}")
        
        successful = [r for r in self.results if r.handshake_ok]
        failed = [r for r in self.results if not r.handshake_ok]
        
        print(f"\nTotal: {len(self.results)} | Success: {len(successful)} | Failed: {len(failed)}")
        
        # Check for AWG-specific errors
        awg_errors = [r for r in failed if "Line unrecognized" in r.error or "Jc" in r.error]
        if awg_errors:
            print(f"\n⚠️  {len(awg_errors)} tests failed due to missing AmneziaWG!")
            print(f"   Standard WireGuard cannot parse AWG parameters.")
        
        if successful:
            successful.sort(key=lambda x: x.ping_avg_ms if x.ping_avg_ms > 0 else 9999)
            
            print(f"\n{'─'*70}")
            print(f"{'Jc':<4} {'Jmin':<5} {'Jmax':<5} {'S1':<4} {'S2':<4} "
                  f"{'Ping Avg':<10} {'Loss%':<8} Config")
            print(f"{'─'*70}")
            
            for r in successful[:20]:
                p = r.params
                print(f"{p['Jc']:<4} {p['Jmin']:<5} {p['Jmax']:<5} "
                      f"{p['S1']:<4} {p['S2']:<4} "
                      f"{r.ping_avg_ms:<10.1f} {r.packet_loss:<8.1f} {r.config_name[:30]}")
            
            best = successful[0]
            p = best.params
            print(f"\n{'─'*70}")
            print(f"🏆 BEST: Jc={p['Jc']}, Jmin={p['Jmin']}, Jmax={p['Jmax']}, "
                  f"S1={p['S1']}, S2={p['S2']}")
            print(f"   H1={p['H1']}, H2={p['H2']}, H3={p['H3']}, H4={p['H4']}")
            print(f"   Ping: {best.ping_avg_ms:.1f}ms, Loss: {best.packet_loss:.0f}%")
            
            self._generate_recommended(best)
    
    def _generate_recommended(self, best: TestResult):
        if not self.configs:
            return
        
        params = AWGParams(**best.params)
        generator = ConfigGenerator(str(self.output_dir))
        
        print(f"\n{'─'*70}")
        print("RECOMMENDED CONFIGURATIONS:")
        
        for config in self.configs:
            filepath = generator.generate(config, params, "RECOMMENDED")
            print(f"\n  📄 {filepath}")
            
            with open(filepath, 'r') as f:
                print(f"\n  {'─'*40}")
                for line in f:
                    print(f"  {line.rstrip()}")
                print(f"  {'─'*40}")
    
    def run(self):
        """Main execution"""
        if not self.check_environment():
            sys.exit(1)
        
        if self.load_configs() == 0:
            print(f"\n❌ No .conf files found in {self.config_dir}")
            sys.exit(1)
        
        if self.generate_variations() == 0:
            print("\n❌ No variations generated")
            sys.exit(1)
        
        if self.args.generate_only:
            print(f"\n✓ Generated {len(self.variations)} configs in {self.generated_dir}")
            return
        
        self.run_tests()
        self.save_results()


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AmneziaWG Configuration Tester (requires AmneziaWG, not standard WireGuard)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
IMPORTANT: This tool requires AmneziaWG, not standard WireGuard!

Install AmneziaWG on Ubuntu/Debian:
  sudo add-apt-repository ppa:amnezia/ppa
  sudo apt update
  sudo apt install amneziawg amneziawg-tools

Examples:
  # Basic test
  sudo python3 awg_tester.py -c ./conf
  
  # Set H1-H4 (must match server!)
  sudo python3 awg_tester.py -c ./conf --h1 123456789 --h2 987654321 --h3 111111 --h4 222222
  
  # Specific Jc values
  sudo python3 awg_tester.py -c ./conf --jc-values 1,3,5,10,15
  
  # Generate configs only
  python3 awg_tester.py -c ./conf --generate-only
        """
    )
    
    # Directories
    parser.add_argument('-c', '--config-dir', default='conf',
                       help='Directory with .conf files')
    parser.add_argument('-o', '--output-dir', default='output',
                       help='Output directory')
    
    # H1-H4
    parser.add_argument('--h1', type=int, default=1, help='H1 header')
    parser.add_argument('--h2', type=int, default=2, help='H2 header')
    parser.add_argument('--h3', type=int, default=3, help='H3 header')
    parser.add_argument('--h4', type=int, default=4, help='H4 header')
    
    # Parameter values
    parser.add_argument('--jc-values', help='Jc values (comma-separated)')
    parser.add_argument('--jc-range', type=int, nargs=3, metavar=('START', 'END', 'STEP'))
    parser.add_argument('--jmin-values', help='Jmin values')
    parser.add_argument('--jmin-range', type=int, nargs=3, metavar=('START', 'END', 'STEP'))
    parser.add_argument('--jmax-values', help='Jmax values')
    parser.add_argument('--jmax-range', type=int, nargs=3, metavar=('START', 'END', 'STEP'))
    parser.add_argument('--s1-values', help='S1 values')
    parser.add_argument('--s1-range', type=int, nargs=3, metavar=('START', 'END', 'STEP'))
    parser.add_argument('--s2-values', help='S2 values')
    parser.add_argument('--s2-range', type=int, nargs=3, metavar=('START', 'END', 'STEP'))
    
    # Test options
    parser.add_argument('--ping-target', default='1.1.1.1', help='Ping target')
    parser.add_argument('--ping-count', type=int, default=5, help='Ping count')
    parser.add_argument('--generate-only', action='store_true', help='Only generate configs')
    parser.add_argument('--force', action='store_true', 
                       help='Force testing even without AmneziaWG (will likely fail)')
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║          AmneziaWG Configuration Tester                          ║
║   Requires: awg-quick, awg (AmneziaWG tools)                     ║
║   NOT compatible with standard wg-quick/wg                       ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    print(f"Platform: {platform.system()}")
    print(f"Config dir: {args.config_dir}")
    print(f"H values: H1={args.h1}, H2={args.h2}, H3={args.h3}, H4={args.h4}")
    
    app = AWGTester(args)
    app.run()
    
    print(f"\n{'='*60}")
    print("DONE!")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
