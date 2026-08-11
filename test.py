from triage.extractor import validate_ip, validate_hash, validate_domain, extract_from_text, iter_json, extract_from_wazuh
from triage.lookups.abuseipdb import check_abuseipdb
from triage.lookups.urlhaus import check_urlhaus
from triage.lookups.virustotal import check_virustotal
from triage.cache import init_cache, write_cache, read_cache
from triage.models import IOC, IOC_Type
from triage.combiner import enrich
from triage.cache import init_cache
import time
# tests = ["45.146.164.110", "10.0.0.5", "999.1.1.1", "hello"]

# hash_tests = [
#     "44d88612fea8a8f36de82e1278abb02f", # 32 chars -> MD5
#     "3395856ce81f2b7382dee72602f798b642f14140", # 40 chars -> SHA1
#     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", # 64 chars -> SHA256
#     "zzzz", # not hex -> None
#     "abc123", # hex but wrong length -> None
# ]

# domain_tests = [
#     "evil.com", # valid -> DOMAIN
#     "malware-c2.example-bad.top", # valid -> DOMAIN
#     "sub.domain.co.uk", # valid, multi-part TLD -> DOMAIN
#     "hello", # no dot -> None
#     "8.8.8.8", # an IP, not a domain -> None
#     "file.zzzznotatld", # fake TLD -> None
# ]

# sample = """
# Jun 1 12:03:44 host sshd: Invalid user admin from 45.146.164.110, port 51022.
# File /tmp/payload.bin added (md5 44d88612fea8a8f36de82e1278abb02f).
# DNS query for "evil.com" from workstation 10.0.0.5 ignored.
# """
# alert = {
#     "rule": {"id": "5710", "description": "sshd failed login"},
#     "data": {"srcip": "45.146.164.110", "port": 51022},
#     "syscheck": {"md5_after": "44d88612fea8a8f36de82e1278abb02f"},
#}


# for t in tests:
#     result = validate_ip(t)
#     print(f"{t:20} -> {result}")



# print("\nHash validation tests:")
# for t in hash_tests:
#     results = validate_hash(t)
#     print(f"{t:64} -> {results}")

# print("\nDomain tests:")
# for t in domain_tests:
#     x = validate_domain(t)
#     print(f"{t:30} -> {x}")


# print("\nExtract-from-text results:")
# for ioc in extract_from_text(sample):
#     print(f"  {ioc.type.value:8} {ioc.value}")

# print("\niter_json results:")
# for s in iter_json(alert):
#     print(f"  {s!r}")


# for ioc in extract_from_wazuh("samples/wazuh_sample.json"):
#     print(f"  {ioc.type.value:8} {ioc.value}")

# print (check_abuseipdb("118.25.6.39"))
# print (check_urlhaus("64.89.163.215"))

init_cache()
# print("Cache initialized.")
# write_cache("1.2.3.4", "abuseipdb", {"score": 100, "reports": 5})
# print("fresh read:", read_cache("1.2.3.4", "abuseipdb"))
# print("missing read:", read_cache("9.9.9.9", "abuseipdb"))

# test_ioc = IOC(value="64.89.163.215", type=IOC_Type.IPV4, source="test")
# print(enrich(test_ioc))

test_ioc = IOC(value="64.89.163.215", type=IOC_Type.IPV4, source="test")

start = time.time()
print(enrich(test_ioc))
print(f"first run: {time.time() - start:.2f}s")

start = time.time()
print(enrich(test_ioc))
print(f"second run: {time.time() - start:.2f}s")