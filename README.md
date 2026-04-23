# network-analysis-tools

Scripts for analyzing packet captures.

## pcap_analyzer.py

Takes a `.pcap` or `.pcapng` file and produces a CSV breaking down every conversation (grouped by 4-tuple). Installs its own dependencies on first run.

**Each row in the output includes:**
- Transport and application layer protocol
- Client/server direction, packet counts, and byte counts
- Encryption status, cipher suite, and key exchange algorithm
- A Wireshark display filter to jump straight to that conversation
- Country, ASN, and blacklist status for the remote IP

**GeoIP** uses the [DB-IP lite databases](https://db-ip.com/db/lite/) (included). Place `.mmdb` or `.mmdb.gz` files in the same directory as the script, or pass `--db-dir`.

**Blacklists** are pulled from Spamhaus DROP, Emerging Threats, and Feodo Tracker at runtime and cached for 24 hours.

### Usage

```
py pcap_analyzer.py <capture.pcap> [--output results.csv] [--db-dir PATH] [--skip-geo] [--skip-blacklist]
```
