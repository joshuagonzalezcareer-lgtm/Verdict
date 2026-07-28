from triage.extractor import validate_ip, validate_hash, validate_domain

tests = ["45.146.164.110", "10.0.0.5", "999.1.1.1", "hello"]

hash_tests = [
    "44d88612fea8a8f36de82e1278abb02f", # 32 chars -> MD5
    "3395856ce81f2b7382dee72602f798b642f14140", # 40 chars -> SHA1
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", # 64 chars -> SHA256
    "zzzz", # not hex -> None
    "abc123", # hex but wrong length -> None
]

domain_tests = [
    "evil.com", # valid -> DOMAIN
    "malware-c2.example-bad.top", # valid -> DOMAIN
    "sub.domain.co.uk", # valid, multi-part TLD -> DOMAIN
    "hello", # no dot -> None
    "8.8.8.8", # an IP, not a domain -> None
    "file.zzzznotatld", # fake TLD -> None
]

for t in tests:
    result = validate_ip(t)
    print(f"{t:20} -> {result}")



print("\nHash validation tests:")
for t in hash_tests:
    results = validate_hash(t)
    print(f"{t:64} -> {results}")

print("\nDomain tests:")
for t in domain_tests:
    x = validate_domain(t)
    print(f"{t:30} -> {x}")