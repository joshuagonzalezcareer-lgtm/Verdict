# Validates what is a valid ip address
import ipaddress
from triage.models
import IOC, IOC_Type

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
