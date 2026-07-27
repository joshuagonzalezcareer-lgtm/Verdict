from triage.extractor import validate_ip, validate_hash

tests = ["45.146.164.110", "10.0.0.5", "999.1.1.1", "hello"]

for t in tests:
    result = validate_ip(t)
    print(f"{t:20} -> {result}")

hash_tests = [
    "44d88612fea8a8f36de82e1278abb02f", # 32 chars -> MD5
    "3395856ce81f2b7382dee72602f798b642f14140", # 40 chars -> SHA1
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", # 64 chars -> SHA256
    "zzzz", # not hex -> None
    "abc123", # hex but wrong length -> None
]

print("\nHash validation tests:")
for t in hash_tests:
    results = validate_hash(t)
    print(f"{t:64} -> {results}")
