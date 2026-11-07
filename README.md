# dns-blocklist

Exact-domain blocklist for Pi-hole gravity. Pull `blocklist.txt` from the `main` branch.

Pi-hole treats each plain domain as one exact name. `example.com` does not block `ads.example.com`. A line starting with `#` is a comment.

StevenBlack's hosts file lists exact hostnames. oisd small (`domainswild2`) and HaGeZi Multi PRO (`wildcard/pro-onlydomains.txt`) publish a name when they mean that name and its subdomains. This file keeps every name those lists actually publish, including children of a parent that is also listed. It does not invent the unpublished subdomains a wildcard would have covered, so it is not a substitute for loading those lists as wildcards.

Core sign-in, auth-provider, and other primary service names are left out. See the header in `blocklist.txt`.

Rebuild from local snapshots, then run the tests:

```
python3 tools/build_blocklist.py --stevenblack hosts.txt --oisd oisd.txt --hagezi hagezi.txt --output blocklist.txt
python3 -m unittest tests/test_build_blocklist.py
```
