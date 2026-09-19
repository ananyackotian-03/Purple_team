ALLOWED_EXECUTABLES = {"/usr/bin/bash", "/usr/bin/sh", "/usr/bin/cat", "/usr/bin/rm", "/usr/bin/curl"}
ALLOWED_BASH_COMMANDS = {
    "whoami",
    "cat /etc/shadow",
    "rm /tmp/sentinelforge_test_evidence.log",
    # Web application testing commands (sentinel-controlled vulnerable Flask app)
    "curl -s -X POST http://vulnerable-app:5000/api/ping -H Content-Type: application/json -d {\"host\":\"127.0.0.1\"}",
    "curl -s -X POST http://vulnerable-app:5000/api/files/read -H Content-Type: application/json -d {\"path\":\"/etc/hostname\"}",
    "curl -s -X POST http://vulnerable-app:5000/login -d \"username=admin&password=admin123\"",
    "curl -s -X POST http://vulnerable-app:5000/api/search -H Content-Type: application/json -d {\"q\":\"test\"}",
}
