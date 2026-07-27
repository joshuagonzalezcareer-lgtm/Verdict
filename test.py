from triage.extractor import validate_ip

tests = ["45.146.164.110", "10.0.0.5", "999.1.1.1", "hello"]

for t in tests:
    result = validate_ip(t)
    print(f"{t:20} -> {result}")