"""Stand-in for the esphome CLI used by the tests.

The last argument is a JSON "device file" that scripts the behaviour:
  {"lines": [...], "exit": 0, "hang": false, "config_output": "...", "config_exit": 0}
Every invocation appends its argv to "<device file>.argv" for assertions.
"""
import json
import sys
import time

argv = sys.argv[1:]
path = argv[-1]
spec = json.load(open(path))
with open(path + ".argv", "a") as fh:
    fh.write(json.dumps(argv) + "\n")
if "config" in argv:
    sys.stdout.write(spec.get("config_output", ""))
    sys.exit(spec.get("config_exit", 0))
for line in spec.get("lines", []):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
if spec.get("hang"):
    time.sleep(3600)
sys.exit(spec.get("exit", 0))
