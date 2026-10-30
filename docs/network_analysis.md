# Stage 7 — Network metadata and authorised offline packets

`ConnectionMonitor` in `src/scry_security/collectors/network/connection_monitor.py`
uses psutil for cross-platform TCP/connected-UDP metadata. It emits canonical
`network_connection` events with local and remote addresses, ports, protocol,
status and PID when available. Listeners and unconnected UDP sockets do not have
a destination and are omitted by this connection-observation adapter.

Each poll compares tuples against the preceding snapshot. Repeated snapshots of
the same tuple do not create repeated observations. A tuple that disappears and
returns can be observed again. Connections that begin and end between polls are
invisible; a snapshot is not a count of packets, attempts or successful sessions.
Local/remote metadata alone does not prove outbound direction.

```python
from scry_security.collectors.network.connection_monitor import ConnectionMonitor

monitor = ConnectionMonitor(watched_ports=frozenset({4444}))
batch = monitor.poll()
print(batch.status, len(batch.results))
```

The default watched-port policy is empty. Only explicit watched ports set
`details.policy_violation`; five such new observations to one destination in
five minutes can trigger SCRY-NETWORK-001. An unusual port by itself is not an
alert. Review application purpose and local policy before choosing watched ports.
No service-discovery or compromise ATT&CK mapping is inferred from this metadata.

Permissions vary. In particular, Linux may silently omit connections inaccessible
to the caller. The returned source message always states best-effort coverage.
Use narrow local privileges and document the resulting visibility rather than
running the dashboard as root. [psutil documents these limits](https://psutil.readthedocs.io/stable/).

## Optional packet analysis

Install `.[packet-analysis]` in the virtual environment to add Scapy. The
`analyse_pcap` generator in `packet_analyser.py` accepts a local authorised PCAP,
an explicit source OS and hostname. It emits IP/TCP/UDP metadata and observable
DNS queries without retaining packet payloads. It bounds capture size to 128 MiB
and the processed packet count. Malformed packet metadata becomes a parse error.

No capture interface is opened. Live capture is not implemented. If live capture
is added later, Windows will need an appropriate capture driver such as Npcap,
and Linux capture permissions/capabilities must be configured explicitly. Offline
synthetic analysis works without granting live capture rights. See
[Scapy's offline capture documentation](https://scapy.readthedocs.io/en/stable/usage.html).

Run `python -m pytest tests/collectors/test_network.py` in the virtual environment.
Tests mock Windows and Linux snapshots and generate a synthetic TCP/DNS PCAP
locally. The PCAP test skips explicitly if the optional Scapy extra is absent.

## CLI replay and committed synthetic datasets

```powershell
.\.venv\Scripts\python.exe -m scry_security --replay sample_logs/network/suspicious/connections.jsonl --synthetic --policy examples/detection-policy.toml
.\.venv\Scripts\python.exe -m scry_security --pcap sample_logs/network/suspicious/dns.pcap --capture-os linux --capture-host linux-lab --synthetic --policy examples/detection-policy.toml --database data/demo.sqlite
```

The metadata fixture produces watched-port and watched-destination findings with
the example policy. Its benign counterpart produces none. The three DNS queries
in the saved PCAP produce one watched-domain finding. Origin OS and hostname
must be supplied explicitly; reading a capture on Windows does not make its
source Windows. No packets are sent by fixture generation or replay.

`--max-packets` bounds analysis. If more packets remain, the command reports a
budget error and exits 2 rather than claiming the capture was fully analysed.
Malformed capture data is also reported safely. Packet observations stay distinct
from connection observations; packet counts are not presented as connection counts.
Rebuild fixtures using `python scripts/generate_network_samples.py` with the
optional Scapy extra installed.

Watched-destination policy also supports a TCP initiation lead when three new
`SYN_SENT` observations target a watched network. This is narrower evidence of
outbound initiation than a generic established snapshot. Short-lived states can
be missed by polling; neither absent observations nor unknown direction prove
that no outbound traffic occurred.
