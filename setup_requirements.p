import os
import subprocess
import sys

def run_command(command):
    """Run a shell command and handle errors."""
    try:
        subprocess.run(command, shell=True, check=True, executable="/bin/bash")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)

def main():
    env_path = os.path.join(os.getcwd(), "env")
    
    print("Setting up the virtual environment and installing dependencies...")

    # Create virtual environment
    if not os.path.exists(env_path):
        print("Creating virtual environment...")
        run_command(f"python3 -m venv {env_path}")

    # Activate virtual environment and install dependencies
    activate_env = f"source {env_path}/bin/activate"
    
    print("Installing required packages...")
    run_command(f"{activate_env} && pip install --upgrade pip && pip install -r requirements.txt")

    print("Setup completed successfully!")

if __name__ == "__main__":
    main()
