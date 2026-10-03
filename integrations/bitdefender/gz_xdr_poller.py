#!/usr/bin/env python3
"""
Bitdefender GravityZone XDR -> Splunk (index=xdr) | PULL mode poller

Runs on the Splunk server (cron, every 5 minutes). It PULLS data from the
GravityZone Public API and writes it to the local Splunk HEC over plain HTTP,
so nothing in the existing Splunk/HEC setup has to change.

Collected data (module field in Splunk):
  - quarantine       : threats detected/quarantined on endpoints (Quarantine API)
  - incident         : XDR/EDR incidents (Incidents API, if available on the license)
  - endpoint-status  : managed endpoints inventory + applied policy (Network API, hourly)
  - poller-heartbeat : one event per run (proves the pipeline works)

Only Python standard library is used (no pip, no third-party packages).

Config: /etc/gz_xdr.conf  (chmod 600, owner root), format:
    GZ_API_KEY=xxxxxxxx
    GZ_API_URL=https://cloudgz.gravityzone.bitdefender.com/api
    HEC_URL=http://127.0.0.1:8088/services/collector
    HEC_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    GZ_COMPANY_ID=xxxxxxxxxxxxxxxxxxxxxxxx   (for Incidents API, parentId)

Run once by hand:  sudo python3 /opt/gz_xdr/gz_xdr_poller.py
"""
import base64
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid

CONF_FILE = os.environ.get("GZ_XDR_CONF", "/etc/gz_xdr.conf")
STATE_FILE = os.environ.get("GZ_XDR_STATE", "/var/lib/gz_xdr/state.json")
INDEX = "xdr"
SOURCETYPE = "bitdefender:gravityzone"
SOURCE = "gz_xdr_poller"
ENDPOINT_STATUS_EVERY = 3600  # seconds


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def load_conf():
    conf = {}
    with open(CONF_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip().strip('"')
    for k in ("GZ_API_KEY", "HEC_TOKEN"):
        if not conf.get(k):
            sys.exit(f"[-] {k} missing in {CONF_FILE}")
    conf.setdefault("GZ_API_URL", "https://cloudgz.gravityzone.bitdefender.com/api")
    conf.setdefault("HEC_URL", "http://127.0.0.1:8088/services/collector")
    return conf


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"seen_quarantine": [], "seen_incidents": [], "last_endpoint_status": 0}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    state["seen_quarantine"] = state["seen_quarantine"][-5000:]
    state["seen_incidents"] = state["seen_incidents"][-5000:]
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


class GravityZone:
    def __init__(self, base, key):
        self.base = base.rstrip("/")
        self.auth = "Basic " + base64.b64encode((key + ":").encode()).decode()

    def call(self, service, method, params, retries=3):
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params,
                           "id": str(uuid.uuid4())}).encode()
        url = f"{self.base}/v1.0/jsonrpc/{service}"
        for attempt in range(retries):
            req = urllib.request.Request(url, data=body, method="POST", headers={
                "Authorization": self.auth, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = json.loads(r.read().decode())
                if data.get("error"):
                    raise RuntimeError(json.dumps(data["error"]))
                return data.get("result")
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < retries - 1:
                    time.sleep(20 * (attempt + 1))
                    continue
                raise RuntimeError(f"HTTP {e.code}: {e.read().decode(errors='replace')[:300]}")
        raise RuntimeError("retries exhausted")

    def paged(self, service, method, params, per_page=100, max_pages=20):
        page = 1
        while page <= max_pages:
            res = self.call(service, method, dict(params, page=page, perPage=per_page)) or {}
            for item in res.get("items", []):
                yield item
            if page >= int(res.get("pagesCount", 1) or 1):
                break
            page += 1
            time.sleep(1)


class Hec:
    def __init__(self, url, token):
        self.url = url
        self.headers = {"Authorization": "Splunk " + token, "Content-Type": "application/json"}
        self.host = socket.gethostname()
        self.buf = []

    def add(self, module, event, ts=None):
        ev = dict(event)
        ev["module"] = module
        rec = {"index": INDEX, "sourcetype": SOURCETYPE, "source": SOURCE,
               "host": self.host, "event": ev}
        if ts:
            rec["time"] = ts
        self.buf.append(json.dumps(rec, default=str))

    def flush(self):
        if not self.buf:
            return 0
        data = "\n".join(self.buf).encode()
        req = urllib.request.Request(self.url, data=data, method="POST", headers=self.headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read().decode())
        if resp.get("code", 0) != 0:
            raise RuntimeError(f"HEC error: {resp}")
        n = len(self.buf)
        self.buf = []
        return n


def main():
    conf = load_conf()
    state = load_state()
    gz = GravityZone(conf["GZ_API_URL"], conf["GZ_API_KEY"])
    hec = Hec(conf["HEC_URL"], conf["HEC_TOKEN"])
    stats = {"quarantine": 0, "incident": 0, "endpoint-status": 0, "errors": []}

    # 1) Quarantine (detected threats)
    try:
        seen = set(state["seen_quarantine"])
        for item in gz.paged("quarantine/computers", "getQuarantineItemsList", {}):
            qid = str(item.get("id"))
            if qid in seen:
                continue
            hec.add("quarantine", item)
            state["seen_quarantine"].append(qid)
            seen.add(qid)
            stats["quarantine"] += 1
    except Exception as e:
        stats["errors"].append(f"quarantine: {e}")

    # 2) Incidents (XDR/EDR) - optional, depends on license
    try:
        if not conf.get("GZ_COMPANY_ID"):
            raise RuntimeError("GZ_COMPANY_ID not set in config (skipped)")
        seen = set(state["seen_incidents"])
        for item in gz.paged("incidents", "getIncidentsList", {"parentId": conf["GZ_COMPANY_ID"]}, per_page=500):
            iid = str(item.get("id") or item.get("incidentId"))
            if iid in seen:
                continue
            hec.add("incident", item)
            state["seen_incidents"].append(iid)
            seen.add(iid)
            stats["incident"] += 1
    except Exception as e:
        if "Method not found" in str(e) or "not set" in str(e):
            stats["incidents_note"] = "Incidents API not available on this license (skipped)"
        else:
            stats["errors"].append(f"incidents: {e}")

    # 3) Endpoint inventory / protection status (hourly)
    now = time.time()
    if now - state.get("last_endpoint_status", 0) >= ENDPOINT_STATUS_EVERY:
        try:
            for item in gz.paged("network", "getEndpointsList", {"isManaged": True}):
                hec.add("endpoint-status", item)
                stats["endpoint-status"] += 1
            state["last_endpoint_status"] = now
        except Exception as e:
            stats["errors"].append(f"network: {e}")

    # 4) Heartbeat
    hec.add("poller-heartbeat", {
        "message": "GravityZone XDR poller run",
        "new_quarantine": stats["quarantine"],
        "new_incidents": stats["incident"],
        "endpoints_reported": stats["endpoint-status"],
        "errors": stats["errors"],
        "note": stats.get("incidents_note", ""),
    })

    sent = hec.flush()
    save_state(state)
    log(f"[+] sent={sent} quarantine={stats['quarantine']} incidents={stats['incident']} "
        f"endpoints={stats['endpoint-status']} errors={len(stats['errors'])}")
    for err in stats["errors"]:
        log(f"[!] {err}")


if __name__ == "__main__":
    main()
