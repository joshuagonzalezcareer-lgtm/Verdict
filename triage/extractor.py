# Validates what is a valid ip address
import ipaddress
import tldextract
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

  parsed = tldextract.extract(text)


  # real domain has both a domain and a suffix (ex. "google.com" has domain "google" and suffix "com")
  if not parsed.domain or not parsed.suffix:
    return None

  return IOC(value=text, type=IOC_Type.DOMAIN)