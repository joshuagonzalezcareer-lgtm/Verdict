# Validates what is a valid ip address
from email.mime import text
import ipaddress, tldextract, json
from triage.models import IOC, IOC_Type

def validate_ip(text: str) -> IOC | None:
  try:
    ip = ipaddress.IPv4Address(text)
  except ipaddress.AddressValueError: # not a valid ip (ex. "xxxx")
    return None 

  # Skip valid ip's that are internal or private
  is_skippable = (
    ip.is_private
    or ip.is_loopback
    or ip.is_reserved
    or ip.is_link_local
  )

  if is_skippable:
    return None

  return IOC(value=text, type=IOC_Type.IPV4)

def validate_hash(text: str) -> IOC | None:
  try:
    int(text, 16) # check the string if its a valid hex string
  except ValueError:
    return None

  length_to_type = {
    32: IOC_Type.MD5,
    40: IOC_Type.SHA1,
    64: IOC_Type.SHA256
  }

  ioc_type = length_to_type.get(len(text))

  if ioc_type is None:
    return None

  return IOC(value=text, type=ioc_type)

def validate_domain(text: str) -> IOC | None:
  text = text.lower().rstrip(".") # remove trailing dot if present

  if "@" in text:
    return None

  parsed = tldextract.extract(text)


  # real domain has both a domain and a suffix (ex. "google.com" has domain "google" and suffix "com")
  if not parsed.domain or not parsed.suffix:
    return None

  return IOC(value=text, type=IOC_Type.DOMAIN)

def extract_from_text(text: str) -> list[IOC]:
  junk = "\"',;:(){}[]<>|."

  validators = [validate_ip, validate_hash, validate_domain]

  found: list[IOC] = []

  for token in text.split():
    clean = token.strip(junk)
    if not clean:
      continue

    for validator in validators:
      ioc = validator(clean)
      if ioc is not None:
        found.append(ioc)
        break

  return found

def iter_json(obj):
  # Base case: if the object is a string, yield it
  if isinstance(obj, str):
    yield obj
  # dict maps keys to values ... ex {"key": "value"}
  elif isinstance(obj, dict):
    for value in obj.values():
      yield from iter_json(value)
  # Recurse and yield through all values in the list
  elif isinstance(obj, list):
    for item in obj:
      yield from iter_json(item)

def extract_from_wazuh(path:str) -> list[IOC]:
  # open file and parse json into python objects
  with open(path, "r", encoding="utf-8") as f:
    alert = json.load(f)

    # iterate every string in the alert, extract any IOCs
    found: list[IOC] = []
    for x in iter_json(alert):
      found.extend(extract_from_text(x))

    return found
    
      