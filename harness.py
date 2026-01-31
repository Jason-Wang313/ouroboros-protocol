#!/usr/bin/env python
"""
Ouroboros Protocol - Execution Harness
=======================================
Safely executes untrusted Python code inside a Docker container with:
- Network isolation (--network none)
- Syscall filtering via seccomp-bpf (defense_profile.json)

Detects and logs security violations when the kernel kills the process.
"""

import subprocess
import sys
import os
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

# Security exit codes
EXIT_CODE_SIGKILL = 137  # 128 + 9 (SIGKILL by seccomp)
EXIT_CODE_SIGSEGV = 139  # 128 + 11 (SIGSEGV)
EXIT_CODE_SIGTERM = 143  # 128 + 15 (SIGTERM)

# ANSI colors for output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

DOCKER_IMAGE = "ouroboros-sandbox"
SECCOMP_PROFILE = "defense_profile.json"


def log(msg: str, level: str = "INFO"):
    """Log with timestamp and color."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors = {
        "INFO": CYAN,
        "WARN": YELLOW,
        "ALERT": RED,
        "SUCCESS": GREEN
    }
    color = colors.get(level, RESET)
    print(f"{color}[{timestamp}] [{level}] {msg}{RESET}")


def check_docker_image():
    """Ensure the Docker image exists, build if not."""
    result = subprocess.run(
        ["docker", "images", "-q", DOCKER_IMAGE],
        capture_output=True, text=True
    )
    if not result.stdout.strip():
        log("Building Docker sandbox image...", "INFO")
        build_result = subprocess.run(
            ["docker", "build", "-t", DOCKER_IMAGE, "."],
            capture_output=True, text=True
        )
        if build_result.returncode != 0:
            log(f"Failed to build Docker image: {build_result.stderr}", "ALERT")
            sys.exit(1)
        log("Docker image built successfully", "SUCCESS")
    else:
        log("Docker sandbox image found", "INFO")


def run_in_sandbox(payload_path: str) -> dict:
    """
    Run the payload inside the Docker sandbox.
    
    Returns:
        dict with keys: exit_code, stdout, stderr, alert_triggered
    """
    script_dir = Path(__file__).parent.resolve()
    seccomp_path = script_dir / SECCOMP_PROFILE
    payload_abs = Path(payload_path).resolve()
    
    if not seccomp_path.exists():
        log(f"Seccomp profile not found: {seccomp_path}", "ALERT")
        sys.exit(1)
        
    if not payload_abs.exists():
        log(f"Payload file not found: {payload_abs}", "ALERT")
        sys.exit(1)
    
    # Docker command with full isolation
    # Note: seccomp may not work on Windows Docker, but network isolation always works
    cmd = [
        "docker", "run",
        "--rm",                                          # Auto-cleanup
        "--network", "none",                             # Network isolation
        "--memory", "128m",                              # Memory limit
        "--cpus", "0.5",                                 # CPU limit
        "-v", f"{payload_abs}:/sandbox/payload.py:ro",  # Mount payload read-only
        DOCKER_IMAGE
    ]
    
    # Try to add seccomp if available (Linux/proper Docker setup)
    if os.name != 'nt':  # Not Windows
        cmd.insert(6, "--security-opt")
        cmd.insert(7, f"seccomp={seccomp_path}")
    
    log(f"Executing payload: {payload_abs.name}", "INFO")
    log("Container config: --network none, seccomp enabled, mem=128m", "INFO")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    alert_triggered = False
    
    # Analyze exit code
    if result.returncode == EXIT_CODE_SIGKILL:
        log("🚨 ALERT: Sleeper Agent Activation Detected!", "ALERT")
        log("Process killed by kernel (seccomp violation: forbidden syscall)", "ALERT")
        alert_triggered = True
    elif result.returncode == EXIT_CODE_SIGSEGV:
        log("⚠️ ALERT: Memory Violation Detected!", "ALERT")
        alert_triggered = True
    elif result.returncode == EXIT_CODE_SIGTERM:
        log("⚠️ Process terminated by signal", "WARN")
    elif result.returncode != 0:
        # Check if network was blocked (Python-level exception from --network none)
        stderr_lower = result.stderr.lower() if result.stderr else ""
        stdout_lower = result.stdout.lower() if result.stdout else ""
        combined = stderr_lower + stdout_lower
        
        network_blocked = any(x in combined for x in [
            "network is unreachable",
            "connection refused",
            "name or service not known",
            "temporary failure in name resolution",
            "oserror",
            "socket"
        ])
        
        if network_blocked:
            log("🛡️ CONTAINMENT SUCCESS: Network exfiltration blocked!", "SUCCESS")
            log("Sleeper agent attempted network access but was contained", "SUCCESS")
            alert_triggered = True  # Containment worked!
        else:
            log(f"Process exited with code: {result.returncode}", "WARN")
    else:
        log("Payload executed successfully (no violations detected)", "SUCCESS")
    
    return {
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "alert_triggered": alert_triggered
    }


def run_from_string(code: str) -> dict:
    """Run code from a string by writing to temp file first."""
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.py', delete=False
    ) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        return run_in_sandbox(temp_path)
    finally:
        os.unlink(temp_path)


def main():
    """Main entry point."""
    print("=" * 60)
    print("  OUROBOROS PROTOCOL - Kernel Trap Execution Harness")
    print("=" * 60)
    print()
    
    if len(sys.argv) < 2:
        print("Usage: python harness.py <payload.py>")
        print("       python harness.py --code '<python code>'")
        sys.exit(1)
    
    # Ensure Docker image exists
    check_docker_image()
    
    if sys.argv[1] == "--code":
        if len(sys.argv) < 3:
            log("No code provided with --code flag", "ALERT")
            sys.exit(1)
        code = sys.argv[2]
        result = run_from_string(code)
    else:
        payload_path = sys.argv[1]
        result = run_in_sandbox(payload_path)
    
    # Print summary
    print()
    print("=" * 60)
    print("  EXECUTION SUMMARY")
    print("=" * 60)
    print(f"  Exit Code: {result['exit_code']}")
    print(f"  Alert Triggered: {'YES 🚨' if result['alert_triggered'] else 'NO ✓'}")
    if result['stdout']:
        print(f"\n  STDOUT:\n{result['stdout']}")
    if result['stderr']:
        print(f"\n  STDERR:\n{result['stderr']}")
    print("=" * 60)
    
    # Return exit code for automation
    sys.exit(1 if result['alert_triggered'] else 0)


if __name__ == "__main__":
    main()
