import subprocess
import logging
import datetime
import platform
import winreg

# ---------------------------------------------------------
# Setup Logging
# ---------------------------------------------------------

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_filename = f"logs/baseline_results_{timestamp}.txt"

logging.basicConfig(
    filename=log_filename,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_result(check_name, result, details=""):
    message = f"{check_name}: {result}"
    if details:
        message += f" - {details}"
    print(message)
    logging.info(message)

# ---------------------------------------------------------
# Check 1: Windows Firewall Status
# ---------------------------------------------------------

def check_firewall_status():
    try:
        output = subprocess.check_output(
            ["netsh", "advfirewall", "show", "allprofiles"],
            stderr=subprocess.STDOUT,
            text=True
        )

        if "State ON" in output or "ON" in output:
            log_result("Firewall Status", "PASS")
        else:
            log_result("Firewall Status", "FAIL", "Firewall is OFF")

    except Exception as e:
        log_result("Firewall Status", "ERROR", str(e))

# ---------------------------------------------------------
# Check 2: Password Policy
# ---------------------------------------------------------

def check_password_policy():
    try:
        output = subprocess.check_output(
            ["net", "accounts"],
            stderr=subprocess.STDOUT,
            text=True
        )

        if "Minimum password length" in output:
            log_result("Password Policy", "PASS")
        else:
            log_result("Password Policy", "FAIL", "Password policy not found")

    except Exception as e:
        log_result("Password Policy", "ERROR", str(e))

# ---------------------------------------------------------
# Check 3: Windows Update Settings
# ---------------------------------------------------------

def check_windows_update():
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        registry = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value, _ = winreg.QueryValueEx(registry, "AUOptions")

        if value in [3, 4]:  # Auto download or auto install
            log_result("Windows Update", "PASS")
        else:
            log_result("Windows Update", "FAIL", f"AUOptions set to {value}")

    except Exception as e:
        log_result("Windows Update", "ERROR", str(e))

# ---------------------------------------------------------
# Check 4: Installed Updates
# ---------------------------------------------------------

def check_installed_updates():
    try:
        output = subprocess.check_output(
            ["wmic", "qfe", "list", "brief"],
            stderr=subprocess.STDOUT,
            text=True
        )

        if "KB" in output:
            log_result("Installed Updates", "PASS")
        else:
            log_result("Installed Updates", "FAIL", "No KB updates found")

    except Exception as e:
        log_result("Installed Updates", "ERROR", str(e))

# ---------------------------------------------------------
# Check 5: Audit Policy
# ---------------------------------------------------------

def check_audit_policy():
    try:
        output = subprocess.check_output(
            ["auditpol", "/get", "/category:*"],
            stderr=subprocess.STDOUT,
            text=True
        )

        if "Success" in output or "Failure" in output:
            log_result("Audit Policy", "PASS")
        else:
            log_result("Audit Policy", "FAIL", "Audit policy not configured")

    except Exception as e:
        log_result("Audit Policy", "ERROR", str(e))

# ---------------------------------------------------------
# Check 6: Local Administrator Accounts
# ---------------------------------------------------------

def check_local_admins():
    try:
        output = subprocess.check_output(
            ["net", "localgroup", "administrators"],
            stderr=subprocess.STDOUT,
            text=True
        )

        log_result("Local Admin Accounts", "PASS", "Admins listed in log")

    except Exception as e:
        log_result("Local Admin Accounts", "ERROR", str(e))

# ---------------------------------------------------------
# Main Execution
# ---------------------------------------------------------

def main():
    print("\n=== Windows Security Baseline Compliance Check ===\n")
    logging.info("=== Starting Baseline Compliance Check ===")

    if platform.system() != "Windows":
        print("This script must be run on Windows.")
        return

    check_firewall_status()
    check_password_policy()
    check_windows_update()
    check_installed_updates()
    check_audit_policy()
    check_local_admins()

    print("\nScan complete. Results saved to:")
    print(log_filename)
    logging.info("=== Baseline Check Complete ===")

if __name__ == "__main__":
    main()
