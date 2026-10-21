"""
Automated Test Suite - Network Monitoring & Maintenance System (NMMS)
=====================================================================
Companion file to the Test Plan & Test Cases document (Week 3 task).

The file has two parts:
  1. A small reference implementation of the system under test (SUT), so the
     suite runs on its own. Replace `NetworkMonitoringSystem` with your real
     module/API client when you test the actual system.
  2. A unittest suite that automates test cases TC-01 to TC-13 from the
     document (functional, performance and security).

Run:
    python test_network_monitoring.py            # run all tests
    python test_network_monitoring.py -v         # verbose output
    python -m unittest test_network_monitoring.TestSecurity   # one group
"""

import hashlib
import hmac
import ipaddress
import os
import re
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


# ---------------------------------------------------------------------------
# PART 1 - SYSTEM UNDER TEST (reference implementation)
# ---------------------------------------------------------------------------
class AccessDenied(Exception):
    """Raised when a user lacks permission for an action."""


class ValidationError(Exception):
    """Raised when input data is invalid."""


class NetworkMonitoringSystem:
    MAX_FAILED_LOGINS = 3
    ROLES = {"admin": {"add", "delete", "view", "backup"},
             "viewer": {"view"}}

    def __init__(self, ping_function=None):
        self._users = {}          # username -> dict(salt, hash, role, failed, locked)
        self._devices = {}        # ip -> dict(name, status)
        self._alerts = []         # list of dict
        self._backups = {}        # ip -> list of config versions
        self._ping = ping_function or (lambda ip: True)

    # ----- user management & authentication -----
    @staticmethod
    def _hash(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)

    def create_user(self, username, password, role="viewer"):
        if role not in self.ROLES:
            raise ValidationError("Unknown role")
        salt = os.urandom(16)
        self._users[username] = {"salt": salt, "hash": self._hash(password, salt),
                                 "role": role, "failed": 0, "locked": False}

    def login(self, username, password):
        user = self._users.get(username)
        if not user or user["locked"]:
            return False
        if hmac.compare_digest(user["hash"], self._hash(password, user["salt"])):
            user["failed"] = 0
            return True
        user["failed"] += 1
        if user["failed"] >= self.MAX_FAILED_LOGINS:
            user["locked"] = True
        return False

    def is_locked(self, username):
        return self._users[username]["locked"]

    def _require(self, username, permission):
        role = self._users[username]["role"]
        if permission not in self.ROLES[role]:
            raise AccessDenied(f"{username} ({role}) may not '{permission}'")

    # ----- device inventory -----
    _NAME_RE = re.compile(r"^[A-Za-z0-9_\-\. ]{1,50}$")

    def add_device(self, username, name, ip):
        self._require(username, "add")
        if not self._NAME_RE.match(name):
            raise ValidationError("Invalid device name")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValidationError("Invalid IP address")
        if ip in self._devices:
            raise ValidationError("Duplicate IP address")
        self._devices[ip] = {"name": name, "status": "UNKNOWN"}

    def delete_device(self, username, ip):
        self._require(username, "delete")
        self._devices.pop(ip, None)

    def device_count(self):
        return len(self._devices)

    # ----- monitoring -----
    def poll_device(self, ip):
        dev = self._devices[ip]
        new_status = "UP" if self._ping(ip) else "DOWN"
        if new_status == "DOWN" and dev["status"] != "DOWN":
            self._alerts.append({"ip": ip, "name": dev["name"], "type": "DEVICE_DOWN",
                                 "time": datetime.now().isoformat(timespec="seconds")})
        dev["status"] = new_status
        return new_status

    def poll_all(self, workers=20):
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return dict(zip(self._devices, pool.map(self.poll_device, list(self._devices))))

    def alerts(self):
        return list(self._alerts)

    def dashboard_summary(self):
        up = sum(1 for d in self._devices.values() if d["status"] == "UP")
        down = sum(1 for d in self._devices.values() if d["status"] == "DOWN")
        return {"total": len(self._devices), "up": up, "down": down}

    # ----- backup & reporting -----
    def backup_config(self, username, ip, config_text):
        self._require(username, "backup")
        self._backups.setdefault(ip, []).append(config_text)
        return len(self._backups[ip])          # version number

    def restore_config(self, username, ip, version):
        self._require(username, "backup")
        return self._backups[ip][version - 1]

    def generate_report(self):
        s = self.dashboard_summary()
        lines = [f"NMMS Report - {datetime.now():%Y-%m-%d %H:%M}",
                 f"Total devices: {s['total']}", f"Up: {s['up']}", f"Down: {s['down']}",
                 f"Alerts raised: {len(self._alerts)}"]
        return "\n".join(lines)

    def stored_password_hash(self, username):
        return self._users[username]["hash"]


# ---------------------------------------------------------------------------
# PART 2 - TEST SUITE
# ---------------------------------------------------------------------------
class BaseCase(unittest.TestCase):
    """Pre-testing preparation: a clean system with one admin and one viewer."""

    def setUp(self):
        self.status_map = {}   # ip -> bool, lets tests control device state
        self.nms = NetworkMonitoringSystem(lambda ip: self.status_map.get(ip, True))
        self.nms.create_user("admin1", "Adm!n#2026", "admin")
        self.nms.create_user("viewer1", "View#2026", "viewer")


class TestFunctional(BaseCase):

    def test_TC01_valid_login(self):
        """TC-01: Valid credentials are accepted."""
        self.assertTrue(self.nms.login("admin1", "Adm!n#2026"))

    def test_TC02_invalid_login_and_lockout(self):
        """TC-02: Wrong password rejected; account locks after 3 failures."""
        for _ in range(3):
            self.assertFalse(self.nms.login("admin1", "wrong"))
        self.assertTrue(self.nms.is_locked("admin1"))
        self.assertFalse(self.nms.login("admin1", "Adm!n#2026"))  # locked even if correct

    def test_TC03_add_device_valid(self):
        """TC-03: Admin can add a device with a valid name and IP."""
        self.nms.add_device("admin1", "Core-Router-1", "192.168.1.1")
        self.assertEqual(self.nms.device_count(), 1)

    def test_TC04_add_device_invalid_or_duplicate_ip(self):
        """TC-04: Invalid IP and duplicate IP are rejected."""
        with self.assertRaises(ValidationError):
            self.nms.add_device("admin1", "Bad-Device", "999.10.1.1")
        self.nms.add_device("admin1", "SW-1", "10.0.0.5")
        with self.assertRaises(ValidationError):
            self.nms.add_device("admin1", "SW-2", "10.0.0.5")
        self.assertEqual(self.nms.device_count(), 1)

    def test_TC05_device_status_detection(self):
        """TC-05: Reachable device is UP; unreachable device is DOWN."""
        self.nms.add_device("admin1", "PC-1", "192.168.1.10")
        self.nms.add_device("admin1", "PC-2", "192.168.1.11")
        self.status_map["192.168.1.11"] = False
        result = self.nms.poll_all()
        self.assertEqual(result["192.168.1.10"], "UP")
        self.assertEqual(result["192.168.1.11"], "DOWN")

    def test_TC06_alert_on_device_down(self):
        """TC-06: Exactly one alert is raised when a device goes down."""
        self.nms.add_device("admin1", "Server-1", "192.168.1.20")
        self.nms.poll_device("192.168.1.20")          # UP, no alert
        self.assertEqual(len(self.nms.alerts()), 0)
        self.status_map["192.168.1.20"] = False
        self.nms.poll_device("192.168.1.20")
        self.nms.poll_device("192.168.1.20")          # still down - no duplicate
        alerts = self.nms.alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "DEVICE_DOWN")

    def test_TC07_config_backup_and_restore(self):
        """TC-07: Backed-up configuration can be restored exactly."""
        cfg = "hostname R1\ninterface g0/0\n ip address 192.168.1.1 255.255.255.0"
        v = self.nms.backup_config("admin1", "192.168.1.1", cfg)
        self.assertEqual(v, 1)
        self.assertEqual(self.nms.restore_config("admin1", "192.168.1.1", 1), cfg)

    def test_TC08_report_generation(self):
        """TC-08: Report contains correct device and alert counts."""
        for i, ip in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3"], 1):
            self.nms.add_device("admin1", f"Dev-{i}", ip)
        self.status_map["10.0.0.3"] = False
        self.nms.poll_all()
        report = self.nms.generate_report()
        self.assertIn("Total devices: 3", report)
        self.assertIn("Down: 1", report)
        self.assertIn("Alerts raised: 1", report)


class TestPerformance(BaseCase):

    def test_TC09_poll_100_devices_within_5_seconds(self):
        """TC-09: 100 devices are polled in under 5 seconds."""
        def slow_ping(ip):
            time.sleep(0.05)        # simulate 50 ms network latency
            return True
        nms = NetworkMonitoringSystem(slow_ping)
        nms.create_user("a", "pw12345!", "admin")
        for i in range(1, 101):
            nms.add_device("a", f"Node-{i}", f"10.1.{i // 250}.{i % 250 + 1}")
        start = time.perf_counter()
        nms.poll_all(workers=20)
        elapsed = time.perf_counter() - start
        self.assertEqual(nms.dashboard_summary()["up"], 100)
        self.assertLess(elapsed, 5.0, f"Polling took {elapsed:.2f}s")

    def test_TC10_dashboard_under_50_concurrent_users(self):
        """TC-10: Dashboard stays responsive (avg < 0.5 s) for 50 users."""
        for i in range(1, 51):
            self.nms.add_device("admin1", f"Dev-{i}", f"172.16.0.{i}")
        self.nms.poll_all()

        def request(_):
            t0 = time.perf_counter()
            self.nms.dashboard_summary()
            return time.perf_counter() - t0

        with ThreadPoolExecutor(max_workers=50) as pool:
            times = list(pool.map(request, range(50)))
        self.assertLess(sum(times) / len(times), 0.5)
        self.assertLess(max(times), 2.0)


class TestSecurity(BaseCase):

    def test_TC11_sql_injection_rejected(self):
        """TC-11: SQL-injection style input is rejected, not executed."""
        payloads = ["'; DROP TABLE devices;--", "' OR '1'='1", "admin' --"]
        for p in payloads:
            with self.assertRaises(ValidationError):
                self.nms.add_device("admin1", p, "10.9.9.9")
            self.assertFalse(self.nms.login(p, p))
        self.assertEqual(self.nms.device_count(), 0)

    def test_TC12_role_based_access_control(self):
        """TC-12: A viewer cannot add, delete or back up; admin can."""
        with self.assertRaises(AccessDenied):
            self.nms.add_device("viewer1", "Rogue", "10.0.0.99")
        self.nms.add_device("admin1", "Legit", "10.0.0.98")
        with self.assertRaises(AccessDenied):
            self.nms.delete_device("viewer1", "10.0.0.98")
        with self.assertRaises(AccessDenied):
            self.nms.backup_config("viewer1", "10.0.0.98", "cfg")
        self.assertEqual(self.nms.device_count(), 1)

    def test_TC13_passwords_stored_hashed(self):
        """TC-13: Stored credentials are salted hashes, never plain text."""
        stored = self.nms.stored_password_hash("admin1")
        self.assertNotIn(b"Adm!n#2026", stored)
        self.nms.create_user("admin2", "Adm!n#2026", "admin")   # same password
        self.assertNotEqual(stored, self.nms.stored_password_hash("admin2"))  # unique salt


if __name__ == "__main__":
    unittest.main(verbosity=2)
