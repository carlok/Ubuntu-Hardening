# 🚀 Hetzner VM Podman Provisioner

This orchestrated container automatically provisions a new Ubuntu 24.04 Virtual Machine on Hetzner Cloud, runs the CIS Level 1/Level 2 Cloud VM hardening script, and completely locks down the instance. 

It is designed to create a secure, production-ready, rootless Podman node out of the box.

## ✨ Features
- **Hetzner API Integration**: Automatically creates the Server and Cloud Firewall.
- **Auto-Hardening**: Uploads and executes the `Cloud-Ubuntu-Hardening-2026.sh` script to secure the kernel, filesystem bindings (`tmpfs`), and logging (`auditd`/`journald`).
- **Secure Randomization**: 
  - Generates a random unprivileged user.
  - Automatically installs Podman for rootless container execution.
  - Generates an RSA key-pair (saves the private key securely to your host machine).
  - Assigns a random high port (e.g. `45821`) to the SSH server.
- **Automated Lockdown**: Using the Hetzner Firewall API, it physically drops Port `22` and only opens the new random SSH high-port to the internet.

---

## 🛠️ Usage

### 1. Configure the `.env` file
Copy `.env.example` to `.env` and fill in your Hetzner API key.
```bash
cp .env.example .env
nano .env
```
*(You can optionally override options like the Region, Server Type, or Username in this file).*

### 2. Copy the Hardening Script
Ensure you copy the hardened bash script from the parent folder into this provisioner directory so Podman can bundle it:
```bash
cp ../Cloud-Ubuntu-Hardening-2026.sh .
```

### 3. Build & Run
You can run this container manually, or use the provided `run.sh` script to build and run the Podman container (it handles mounting your local volume, which is required to save the generated private SSH key).

```bash
chmod +x run.sh
./run.sh
```

### 4. Connection
Once the orchestration finishes, the python script will output exactly how to connect to your new, fully locked-down host:
```bash
✅ PROVISIONING COMPLETE!
Server IP:    xxx.xxx.xxx.xxx
SSH Port:     48123
Username:     podman_user_a1b2c3d4
Private Key:  (Saved in your host volume as id_rsa)

# Connect via:
ssh -i ./keys/id_rsa -p 48123 podman_user_a1b2c3d4@xxx.xxx.xxx.xxx
```
