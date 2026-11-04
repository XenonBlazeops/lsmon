#!/usr/bin/env python3
"""Install the disabled LSMON provisioner identity and units on vmi3626301."""
import os, platform, shutil, subprocess
from pathlib import Path

HOST="vmi3626301"; SOURCE=Path("/home/ubuntu/lsmon-provisioner-identity"); UNIT_DIR=Path("/etc/systemd/system"); ENV=Path("/etc/lsmon/provisioner.env"); STATE=Path("/var/lib/lsmon-provisioner")
def run(command): subprocess.run(command,check=True)
if os.geteuid()!=0 or platform.node().split(".")[0]!=HOST: raise SystemExit("STOP: run as root on vmi3626301 only")
if not (SOURCE/"systemd/lsmon-provisioner.service").is_file() or not (SOURCE/"systemd/lsmon-provisioner.timer").is_file(): raise SystemExit("STOP: staged unit files are missing")
if ENV.exists(): raise SystemExit(f"STOP: {ENV} already exists; preserve and review it manually")
run(["id","-u","lsmon"])
if subprocess.run(["id","-u","lsmon-provisioner"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
    run(["useradd","--system","--no-create-home","--shell","/usr/sbin/nologin","--groups","lsmon","lsmon-provisioner"])
STATE.mkdir(parents=True,exist_ok=True); run(["chown","lsmon-provisioner:lsmon-provisioner",str(STATE)]); run(["chmod","0700",str(STATE)])
ENV.parent.mkdir(parents=True,exist_ok=True); ENV.write_text("# Deliberately empty. Root adds only the dedicated worker's approved environment later.\n",encoding="utf-8"); run(["chown","root:lsmon-provisioner",str(ENV)]); run(["chmod","0640",str(ENV)])
shutil.copy2(SOURCE/"systemd/lsmon-provisioner.service",UNIT_DIR/"lsmon-provisioner.service"); shutil.copy2(SOURCE/"systemd/lsmon-provisioner.timer",UNIT_DIR/"lsmon-provisioner.timer")
run(["systemctl","daemon-reload"]); run(["systemctl","disable","--now","lsmon-provisioner.service"]); run(["systemctl","disable","--now","lsmon-provisioner.timer"])
timer_state=subprocess.run(["systemctl","is-enabled","lsmon-provisioner.timer"],text=True,capture_output=True).stdout.strip()
if timer_state != "disabled": raise SystemExit(f"STOP: provisioner timer is not disabled: {timer_state or 'unknown'}")
print("PROVISIONER_IDENTITY_STAGE_READY")
print("Dedicated identity and hardened units installed but disabled; provisioner.env contains no values.")
