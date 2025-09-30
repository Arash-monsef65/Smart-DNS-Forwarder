import subprocess
import os
import sys
import time

def main():
    """
    Launches one DNS server process per available CPU core.
    """
    try:
        cpu_count = len(os.sched_getaffinity(0))
    except AttributeError:
        cpu_count = os.cpu_count() or 1
    
    print(f"--- DNS Multi-Process Launcher ---")
    print(f"Detected {cpu_count} available CPU cores. Starting a DNS server process for each.")

    processes = []
    python_executable = "python3"
    server_script = "/opt/dns/dns_server_prod.py"

    for i in range(cpu_count):
        print(f"Starting server process {i+1}/{cpu_count}...")
        try:
            process = subprocess.Popen([python_executable, server_script])
            processes.append(process)
        except Exception as e:
            print(f"Failed to start process {i+1}: {e}")
    
    if not processes:
        print("Error: No server processes were started.")
        sys.exit(1)

    print(f"\n{len(processes)} DNS server processes are running in the background.")
    print("You can monitor them with: htop -p $(pgrep -d, -f dns_server_prod.py)")
    print("This launcher will now wait. Press Ctrl+C to stop this launcher (processes will keep running).")

    try:
        # Keep the main launcher script alive
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nLauncher stopped.")

if __name__ == "__main__":
    main()

