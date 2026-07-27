from dataclasses import dataclass
from enum import Enum

class IOC_Type(str, Enum):
  IPV4 = "ipv4"
  DOMAIN = "domain"
  MD5 = "md5"
  SHA1 = "sha1"
  SHA256 = "sha256"

@dataclass(frozen=True)
class IOC
  value: str
  type: IOC_Type
  source: str = ""
