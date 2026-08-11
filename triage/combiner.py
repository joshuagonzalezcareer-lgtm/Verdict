from triage.models import IOC_Type
from triage.lookups.abuseipdb import check_abuseipdb
from triage.lookups.virustotal import check_virustotal
from triage.lookups.urlhaus import check_urlhaus
from triage.cache import read_cache, write_cache, init_cache

def cache_lookup(ioc_value, source, lookup_function):
    cached = read_cache(ioc_value, source)
    if cached is not None:
        return cached # skip the API

    result = lookup_function(ioc_value)
    if result is not None:
        write_cache(ioc_value, source, result)
    return result

def enrich(ioc):
    results = {}

    if ioc.type == IOC_Type.IPV4:
        results['abuseipdb'] = cache_lookup(ioc.value, 'abuseipdb', check_abuseipdb)
        results['virustotal'] = cache_lookup(ioc.value, 'virustotal', check_virustotal)
    elif ioc.type == IOC_Type.DOMAIN:
        results['urlhaus'] = cache_lookup(ioc.value, 'urlhaus', check_urlhaus)

    return results