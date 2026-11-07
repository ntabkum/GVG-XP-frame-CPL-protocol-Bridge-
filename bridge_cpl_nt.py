"""
NAVA - CPL bridge: WebSocket -> K-Frame. Tested with Zurich XP Frame V 17.7.1

Modes
  default   DRY-RUN. Logs what it would do, touches nothing.
  --live    


"""
import argparse
import asyncio
import json
import logging
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ET

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

START_MARKER = bytes.fromhex("b9916f84")
END_MARKER = bytes.fromhex("3762c5d9")
MSG_CONNECT = 0x001F
HEADER_LEN = 12

# Origins allowed to drive the switcher. A page opened from file:// sends "null".
ALLOWED_ORIGINS = [None, "null", "http://localhost", "http://127.0.0.1"]


# --------------------------------------------------------------------------
# Framing / message encoding
# --------------------------------------------------------------------------
def build_message(msg_type, body=b"", field8=0, byte_a=0, byte_b=2):
    """12-byte CPL header + body (all big-endian). Checksum = sum of header fields."""
    body_len = len(body)
    checksum = byte_a + byte_b + msg_type + field8 + body_len
    hdr = struct.pack(">BBHHHI", byte_a, byte_b, msg_type, field8, body_len, checksum)
    return hdr + body


def wrap_frame(message):
    """TCP adapter framing: start marker, u16 BE length, message, end marker."""
    if len(message) > 0xFFFF:
        raise ValueError("message too long")
    return START_MARKER + struct.pack(">H", len(message)) + message + END_MARKER


def parse_message(msg):
    """-> dict(type, field8, body, checksum_ok) or raises ValueError."""
    if len(msg) < HEADER_LEN:
        raise ValueError(f"message shorter than header ({len(msg)} bytes)")
    a, b, mtype, f8, blen, csum = struct.unpack(">BBHHHI", msg[:HEADER_LEN])
    body = msg[HEADER_LEN:HEADER_LEN + blen]
    ok = (csum == (a + b + mtype + f8 + blen)) if b == 2 else True
    return {"a": a, "b": b, "type": mtype, "field8": f8, "len": blen,
            "body": body, "checksum_ok": ok, "truncated": len(body) != blen}


def build_connect_request(panel_name):
    body = struct.pack(">HH", 1, 0) + panel_name.encode("ascii") + b"\x00"
    return wrap_frame(build_message(MSG_CONNECT, body))


def build_frame(msg_type, body):
    return wrap_frame(build_message(msg_type, body))


def macro_frame(n):
    """Macro register n (1-65536). Body bytes 8-9 = u16 BE (n-1); verified 1,2,3,7,17,999."""
    return build_frame(0x0005, bytes([0, 2, 0, 0, 0x77, 0, 0, 0]) + struct.pack(">H", n - 1) + b"\x00\x00")


def xpt_frame(me, side, src):
    """Crosspoint. Byte 7 = (bus<<4)|(me-1) with me 4 = PGM/PST (pgm = bus A 0x03, pst = bus B 0x13):
    verified ME1 A/B, ME2 A, PGM/PST A src 1-3 and B src 1-2. ME2 B, ME3 and higher sources are
    extrapolated."""
    body = (b"\x10\x4a\x02\x00\x04\x00\x00" + bytes([(0x10 if side == "b" else 0x00) | (me - 1)])
            + struct.pack(">I", src))
    return build_frame(0x0006, body)


def key_frame(k, on, me=1):
    """Keyer on/off. Byte 7 = ((keyer-1)<<4)|(me-1): keyers 1-4 verified on ME1; the ME nibble
    and keyers 5-8 are extrapolated (same pattern as the crosspoint frame)."""
    return build_frame(0x0005, bytes.fromhex("00440000080000") + bytes([((k - 1) << 4) | (me - 1), 1 if on else 0, 0, 0, 0]))


def key_source_frame(k, src, me=1):
    """Keyer fill+key source: two type-6 messages (0x103a, 0x103b) in one adapter frame.
    Byte 7 = ((keyer-1)<<4)|(me-1): keyers 1-2 verified on ME1; 3-8 and the ME nibble extrapolated."""
    b7 = ((k - 1) << 4) | (me - 1)
    msgs = b"".join(
        build_message(0x0006, struct.pack(">H", did) + b"\x02\x00\x08\x00\x00" + bytes([b7]) + struct.pack(">I", src))
        for did in (0x103A, 0x103B))
    return wrap_frame(msgs)


ME_NAMES = {1: "M/E 1", 2: "M/E 2", 3: "M/E 3", 4: "PGM/PST"}  # 1-based, same numbering as xpt_frame


def me_name(me):
    return ME_NAMES.get(me, f"M/E {me}")


def transition_frame(kind, me=1):
    """CUT (0x44) / AUTO TRANS (0x43) on M/E `me` (1=M/E1, 2=M/E2, 3=M/E3, 4=PGM/PST).
    Last body byte = M/E index (0-3); all four verified against KSP captures."""
    return build_frame(0x0005, bytes([0x00, 0x44 if kind == "cut" else 0x43, 0, 0, 0x03, 0, 0, me - 1]))


AUTOTRANS_FRAME = transition_frame("auto", 1)
CUT_FRAME = transition_frame("cut", 1)

# Exact frames captured from the real KSP (replayed verbatim).
KNOWN_FRAMES = {
    "xpt:me1:a:1": bytes.fromhex(
        "b9916f84001800020006000000 0c00000014104a0200040000000000000137 62c5d9".replace(" ", "")),
}


def load_captures(path):
    """Optional user table {key: hex}. Frames are validated before use."""
    import os
    table = dict(KNOWN_FRAMES)
    if not os.path.exists(path):
        return table
    with open(path) as fh:
        for key, hx in json.load(fh).items():
            raw = bytes.fromhex(str(hx).replace(" ", ""))
            frames = FrameReader().feed(raw)
            try:
                good = len(frames) == 1 and all(m["checksum_ok"] for m in parse_messages(frames[0]))
            except ValueError:
                good = False
            if not good:
                logging.error(f"[CAPTURES] '{key}' is not one valid CPL frame; ignored")
                continue
            table[key.lower()] = raw
    return table


class FrameReader:
    """Accumulates bytes and yields complete adapter frames, resyncing on the marker."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data):
        self.buf.extend(data)
        out = []
        while True:
            i = self.buf.find(START_MARKER)
            if i < 0:
                del self.buf[:-3]  # keep possible partial marker
                break
            if i:
                logging.warning(f"[CPL] discarding {i} bytes before start marker")
                del self.buf[:i]
            if len(self.buf) < 6:
                break
            n = struct.unpack(">H", self.buf[4:6])[0]
            if len(self.buf) < n + 10:
                break
            if bytes(self.buf[6 + n:10 + n]) != END_MARKER:
                logging.warning("[CPL] end marker missing; resyncing")
                del self.buf[:4]
                continue
            out.append(bytes(self.buf[6:6 + n]))
            del self.buf[:n + 10]
        return out


def parse_messages(payload):
    """An adapter frame may hold several concatenated CPL messages (keyer source does)."""
    out = []
    while payload:
        m = parse_message(payload)
        if m["truncated"]:
            raise ValueError("truncated message")
        out.append(m)
        payload = payload[HEADER_LEN + m["len"]:]
    return out


def describe(msg):
    try:
        parts = []
        for m in parse_messages(msg):
            parts.append(f"type=0x{m['type']:04x} f8={m['field8']} len={m['len']} "
                         f"csum={'ok' if m['checksum_ok'] else 'BAD'} body={m['body'][:48].hex(' ')}"
                         f"{'...' if len(m['body']) > 48 else ''}")
        return " || ".join(parts)
    except ValueError as e:
        return f"undecodable ({e}): {msg[:48].hex(' ')}"


# --------------------------------------------------------------------------
# One-shot ME status read over the frame's Ethernet Tally port (TCP 2012)
# --------------------------------------------------------------------------
TALLY_PORT = 2012
_TALLY_REQUESTS = ["Configuration-Request", "EngineeringSourceMap-Request", "LogicalSourceMap-Request",
                   "VPEInputMap-Request", "VPEOutputMap-Request", "OutputTallyMap-Request"]


def _etp(inner):
    return f"<ETP>{inner}</ETP>"


def _suite_ok(el, suite):
    try:
        return int(el.attrib.get("Suite", "")) == int(suite)
    except ValueError:
        return True  # no/odd Suite attribute: accept


def read_me_tally(host, me=1, suite=1, port=TALLY_PORT, timeout=5.0):
    """Connect to the frame's Ethernet Tally service, take the initial full VPE contribution
    snapshot for ME<me>, disconnect, and return a dict. Read-only; raises OSError on failure.

    Packet layouts follow eth_tally_sim.py (taken from EthTallyReceiver.exe):
      VPEInputContribution : <VPE Name="ME1"><Input Name="BkgdA">sourceID</Input>...
      VPEOutputContribution: <VPE Name="ME1"><Output Name="PgmA"><Input>BkgdA</Input>...
    me: 1-3 = M/E1-3, 4 = PGM/PST (tally VPE "PGM").
    Returns {"bus_a": id|None, "bus_b": id|None, "pgm": id|None, "pvw": id|None, "onair": "a"|"b",
             "keys": {"1": bool..}}
      pgm/pvw = the on-air / preview bus resolved through the PgmA output (falls back to A/B when
      the output contribution did not arrive); keys come from keyN-fill being in the PgmA output.
    """
    vpe_name = "PGM" if me == 4 else f"ME{me}"   # 4 = PGM/PST bank
    inputs, outs = {}, {}
    got_in = got_out = False
    t_in = None
    buf = ""
    deadline = time.monotonic() + timeout
    sock = socket.create_connection((host, port), timeout=3.0)
    try:
        sock.sendall(_etp(f"<Authentication-Request><Protocol>NT Ethernet Tally</Protocol>"
                          f"<ProtocolVersion>3.0</ProtocolVersion><AppName>NT bridge status</AppName>"
                          f"<AppVersion>1.0</AppVersion><Suite>{suite}</Suite></Authentication-Request>").encode("ascii"))
        subscribed = False
        while time.monotonic() < deadline:
            if got_in and (got_out or time.monotonic() - t_in > 0.5):
                break
            sock.settimeout(max(0.1, min(1.0, deadline - time.monotonic())))
            try:
                data = sock.recv(16384)
            except socket.timeout:
                continue
            if not data:
                raise OSError("frame closed the tally connection")
            buf += data.decode("ascii", "replace")
            while True:
                s = buf.find("<ETP>")
                if s < 0:
                    buf = ""
                    break
                e = buf.find("</ETP>", s)
                if e < 0:
                    buf = buf[s:]
                    break
                pkt, buf = buf[s:e + 6], buf[e + 6:]
                try:
                    root = ET.fromstring(pkt)
                except ET.ParseError:
                    continue
                for el in root:
                    if el.tag == "Authentication" and not subscribed:
                        subscribed = True
                        for r in _TALLY_REQUESTS:
                            sock.sendall(_etp(f"<{r}/>").encode("ascii"))
                        sock.sendall(_etp(f'<TallySubscription-Request><Suite Method="Replace">{suite}</Suite>'
                                          f'</TallySubscription-Request>').encode("ascii"))
                    elif el.tag == "VPEInputContribution" and _suite_ok(el, suite):
                        tn = el.find("Type")
                        if tn is not None and (tn.text or "").strip().lower() == "full":
                            inputs.clear()
                        for vpe in el.findall("VPE"):
                            if vpe.attrib.get("Name", "").upper() != vpe_name:
                                continue
                            for i in vpe.findall("Input"):
                                try:
                                    inputs[i.attrib.get("Name", "").lower()] = int((i.text or "").strip())
                                except ValueError:
                                    inputs.pop(i.attrib.get("Name", "").lower(), None)
                            if not got_in:
                                got_in, t_in = True, time.monotonic()
                    elif el.tag == "VPEOutputContribution" and _suite_ok(el, suite):
                        tn = el.find("Type")
                        if tn is not None and (tn.text or "").strip().lower() == "full":
                            outs.clear()
                        for vpe in el.findall("VPE"):
                            if vpe.attrib.get("Name", "").upper() != vpe_name:
                                continue
                            for o in vpe.findall("Output"):
                                outs[o.attrib.get("Name", "").lower()] = {
                                    (c.text or "").strip().lower() for c in o if (c.text or "").strip()}
                            got_out = True
    finally:
        sock.close()
    if not got_in:
        raise OSError(f"no {vpe_name} input contribution received from the frame within {timeout:.0f}s")
    a, b = inputs.get("bkgda"), inputs.get("bkgdb")
    onair = outs.get("pgma", set()) if got_out else set()
    if "bkgdb" in onair and "bkgda" not in onair:
        pgm, pvw, onair_bus = b, a, "b"
    else:
        pgm, pvw, onair_bus = a, b, "a"
    keys = {}
    if got_out:
        live_inputs = set().union(*(v for k, v in outs.items() if k.startswith("pgm")))
        keys = {str(k): f"key{k}-fill" in live_inputs for k in range(1, 9)}
    return {"bus_a": a, "bus_b": b, "pgm": pgm, "pvw": pvw, "onair": onair_bus, "keys": keys}


# --------------------------------------------------------------------------
# Status decoding (frame -> bridge)
# --------------------------------------------------------------------------
def decode_status(m):
    """Decode one parsed CPL message into a state update, or None if not recognised.

    ASSUMPTION (unverified against hardware): status the frame sends back uses the same body
    layout as the commands this bridge sends, so the same byte patterns are read in reverse:
      crosspoint  body = 10 4a 02 00 04 00 00 | (bus<<4)|(me-1) | src u32      -> ("xpt", me, "a"/"b", src)
      keyer on/off body = 00 44 00 00 08 00 00 | ((keyer-1)<<4)|(me-1) | on ... -> ("key", me, keyer, on)
    If the K-Frame answers differently, the RX log shows the real bytes and only this function
    needs changing.
    """
    body = m["body"]
    if m["type"] in (0x0005, 0x0006) and len(body) >= 12 and body[:2] == b"\x10\x4a" and body[4] == 0x04:
        b7 = body[7]
        if (b7 >> 4) in (0, 1):
            return ("xpt", (b7 & 0x0F) + 1, "b" if b7 >> 4 else "a", struct.unpack(">I", body[8:12])[0])
    if m["type"] in (0x0005, 0x0006) and len(body) >= 9 and body[:2] == b"\x00\x44" and body[4] == 0x08:
        return ("key", (body[7] & 0x0F) + 1, (body[7] >> 4) + 1, bool(body[8]))
    return None


class StatusTracker:
    """Thread-safe mirror of what the frame has told us: crosspoints per M/E bus, keyer on/off."""

    def __init__(self):
        self._lock = threading.Lock()
        self._clear()

    def _clear(self):
        self.xpt = {}            # (me, "a"/"b") -> source
        self.keys = {}           # (me, keyer) -> bool
        self.frames = 0
        self.unrecognised = 0
        self.last_rx = 0.0

    def reset(self):
        with self._lock:
            self._clear()

    def ingest(self, payload):
        """Feed one adapter-frame payload (may hold several CPL messages)."""
        import time
        try:
            msgs = parse_messages(payload)
        except ValueError:
            msgs = []
        with self._lock:
            self.frames += 1
            self.last_rx = time.monotonic()
            for m in msgs:
                upd = decode_status(m) if m["checksum_ok"] else None
                if upd is None:
                    self.unrecognised += 1
                elif upd[0] == "xpt":
                    self.xpt[(upd[1], upd[2])] = upd[3]
                else:
                    self.keys[(upd[1], upd[2])] = upd[3]

    def snapshot(self, me=1):
        with self._lock:
            return {
                "me": me - 1,                                # page uses 0-based M/E
                "pgm": self.xpt.get((me, "a")),              # bus A -> PGM (same mapping as crosspoint action)
                "pvw": self.xpt.get((me, "b")),              # bus B -> PVW
                "keys": {str(k): on for (m_, k), on in sorted(self.keys.items()) if m_ == me},
                "frames": self.frames,
                "unrecognised": self.unrecognised,
            }


# --------------------------------------------------------------------------
# Bridge
# --------------------------------------------------------------------------
class GVGCPLBridge:
    def __init__(self, host, port, live=False, panel_name="NT"):
        self.host, self.port, self.live, self.panel_name = host, port, live, panel_name
        self.sock = None
        self.connected = False
        self._reader_thread = None
        self.captures = dict(KNOWN_FRAMES)
        self.status = StatusTracker()
        self.tally_port = TALLY_PORT
        self._lock = threading.RLock()   # serialises (re)connect and writes on the CPL socket
        self.suite = 1

    def lookup(self, key, label, hint, gen=None):
        frame = self.captures.get(key)
        if frame is None and gen is not None:
            frame = gen()
        if frame is None:
            return label, None, f"no captured frame for '{key}' ({hint}); add it to cpl_captures.json"
        return label, frame, None

    def set_target(self, host, port):
        if (host, port) != (self.host, self.port):
            logging.info(f"[CPL] Target changed to {host}:{port}")
            self.host, self.port = host, port
            self.close()

    def close(self):
        self.connected = False
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    # -- handshake -------------------------------------------------------
    def _handshake(self, sock, track=False):
        """Send Connect request, read reply. Returns (ok, message, leftover_reader).
        track=True feeds any frames that arrive right behind the reply into the status tracker."""
        sock.sendall(build_connect_request(self.panel_name))
        logging.info(f"[CPL] Connect request sent (panel name '{self.panel_name}')")
        reader = FrameReader()
        sock.settimeout(5.0)
        while True:
            data = sock.recv(4096)
            if not data:
                return False, "Frame closed the connection during handshake", reader
            frames = reader.feed(data)
            if frames:
                first = frames[0]
                logging.info(f"[CPL RX] {describe(first)}")
                try:
                    m = parse_message(first)
                except ValueError as e:
                    return False, f"Bad reply: {e}", reader
                if m["type"] != MSG_CONNECT:
                    return False, f"Expected connect reply 0x1f, got 0x{m['type']:04x}", reader
                name = m["body"][4:].split(b"\x00")[0].decode("ascii", "replace")
                if name != self.panel_name:
                    return False, f"Reply panel name '{name}' != '{self.panel_name}'", reader
                for extra in frames[1:]:
                    logging.info(f"[CPL RX] {describe(extra)}")
                    if track:
                        self.status.ingest(extra)
                return True, "CPL session established", reader

    def connect(self):
        with self._lock:
            return self._connect()

    def _connect(self):
        if not self.live:
            return True
        self.close()
        self.status.reset()  # new session: forget anything learned from the previous one
        try:
            logging.info(f"[CPL] TCP connect {self.host}:{self.port} ...")
            sock = socket.create_connection((self.host, self.port), timeout=3.0)
            ok, msg, reader = self._handshake(sock, track=True)
        except OSError as e:
            logging.error(f"[CPL CONNECTION ERROR] {e}")
            return False
        if not ok:
            logging.error(f"[CPL HANDSHAKE FAILED] {msg}")
            sock.close()
            return False
        logging.info(f"[CPL] {msg}")
        self.sock, self.connected = sock, True
        self._reader_thread = threading.Thread(target=self._rx_loop, args=(sock, reader), daemon=True)
        self._reader_thread.start()
        return True

    def _rx_loop(self, sock, reader):
        sock.settimeout(None)
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                for f in reader.feed(data):
                    logging.info(f"[CPL RX] {describe(f)}")
                    self.status.ingest(f)
        except OSError:
            pass
        if self.sock is sock:
            self.connected = False
            logging.warning("[CPL] Session closed")

    # -- status read ------------------------------------------------------
    def read_status(self, me=1, quiet=0.6, timeout=3.0):
        """One-shot read of ME bus A/B crosspoints and keyer on/off. Returns (ok, message, snapshot).

        1. Ethernet Tally (TCP 2012): connect, take the initial full snapshot, disconnect.
        2. CPL session: anything the frame pushed/answered (plus optional 'status:request*'
           frames from cpl_captures.json) fills in what the tally read did not provide.
        Tally values win; CPL only fills in what the tally read did not provide (and is skipped
        entirely when the tally read already returned keyer states).
        """
        if not self.live:
            return True, "dry-run: no frame connected, nothing to read", None
        notes, tally = [], None
        try:
            tally = read_me_tally(self.host, me, self.suite, self.tally_port)
            logging.info(f"[STATUS] tally read {me_name(me)}: {tally}")
        except (OSError, ET.ParseError) as e:
            notes.append(f"tally read failed ({e})")
            logging.warning(f"[STATUS] tally read failed: {e}")

        if not (tally and tally["keys"]):         # tally gave everything -> no need to wait on CPL
            if self.connected or self.connect():
                for key in sorted(k for k in self.captures if k.startswith("status:request")):
                    ok, msg = self.command(f"status request '{key}'", self.captures[key])
                    if not ok:
                        notes.append(msg)
                        break
                t0 = time.monotonic()
                while True:
                    now = time.monotonic()
                    if now - t0 >= timeout or now - max(t0, self.status.last_rx) >= quiet:
                        break
                    time.sleep(0.05)
            else:
                notes.append("CPL not connected")
        cpl = self.status.snapshot(me)

        snap = {"me": me - 1, "frames": cpl["frames"], "unrecognised": cpl["unrecognised"],
                "pgm": cpl["pgm"], "pvw": cpl["pvw"], "keys": dict(cpl["keys"]), "source": "cpl"}
        if tally:
            snap["pgm"] = tally["pgm"] if tally["pgm"] is not None else snap["pgm"]
            snap["pvw"] = tally["pvw"] if tally["pvw"] is not None else snap["pvw"]
            snap["bus_a"], snap["bus_b"] = tally["bus_a"], tally["bus_b"]
            snap["onair"] = tally["onair"]
            snap["keys"] = {**cpl["keys"], **tally["keys"]}   # tally is the fresh point-in-time read
            snap["source"] = "tally" if tally["keys"] else "tally+cpl"
        known = (snap["pgm"] is not None) + (snap["pvw"] is not None) + len(snap["keys"])
        if known:
            keys_on = [k for k, on in snap["keys"].items() if on]
            msg = (f"Status read ({snap['source']}): PGM={snap['pgm']} PVW={snap['pvw']} "
                   f"keys on={','.join(keys_on) or 'none'}")
            if notes:
                msg += "; " + "; ".join(notes)
        else:
            msg = (f"No {me_name(me)} status could be read: " + ("; ".join(notes) or "frame sent nothing decodable")
                   + f" ({cpl['frames']} CPL frame(s), {cpl['unrecognised']} unrecognised)")
        logging.info(f"[STATUS] {msg}")
        return known > 0, msg, snap

    def probe(self, host, port, timeout=3.0):
        """Reachability test. Dry-run/TCP-only unless --live, then full handshake."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            return False, f"Cannot reach {host}:{port} -> {e}"
        try:
            if not self.live:
                return True, f"TCP port open on {host}:{port} (handshake not attempted in dry-run)"
            ok, msg, _ = self._handshake(sock)
            return ok, f"{host}:{port}: {msg}"
        except OSError as e:
            return False, f"{host}:{port}: handshake error {e}"
        finally:
            sock.close()

    # -- commands (not yet encodable) ------------------------------------
    def command(self, label, frame, why=None):
        with self._lock:
            return self._command(label, frame, why)

    def _command(self, label, frame, why=None):
        if frame is None:
            logging.warning(f"[CPL] '{label}' not sent: {why}")
            return False, why
        if not self.live:
            logging.info(f"[DRY-RUN] {label} -> {frame.hex(' ')}")
            return True, "dry-run (nothing sent to frame)"
        if not self.connected and not self.connect():
            return False, "Not connected to frame (see bridge log)"
        try:
            self.sock.sendall(frame)
        except OSError as e:
            self.close()
            return False, f"Write failed: {e}"
        logging.info(f"[CPL TX] {label} -> {frame.hex(' ')}")
        return True, "sent"


def _int(value, lo, hi, name):
    v = int(value)
    if not lo <= v <= hi:
        raise ValueError(f"{name} {v} out of range {lo}-{hi}")
    return v


def _is_status(raw):
    try:
        d = json.loads(raw)
    except ValueError:
        return False
    return isinstance(d, dict) and d.get("action") == "status"


async def handle_message(raw, bridge):
    """Pure message handler (no websocket dependency) -> reply dict."""
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("payload must be a JSON object")
    except (json.JSONDecodeError, ValueError) as e:
        return {"status": "error", "message": f"Invalid JSON: {e}"}

    action = data.get("action")
    mtype = data.get("type") if action is None else None  # page sends {type: SET_CONFIG|TEST_CONNECTION}
    try:
        if action == "crosspoint":
            bus = str(data.get("bus", "pgm")).lower()
            me = _int(data.get("me", 0), 0, 7, "me") + 1
            src = _int(data.get("source", 1), 1, 65535, "source")
            side = "a" if bus in ("pgm", "a") else "b"
            label, frame, why = bridge.lookup(
                f"xpt:me{me}:{side}:{src}", f"crosspoint {me_name(me)} {side.upper()} bus src {src}",
                "only ME1-4 and sources up to 255 are encoded",
                gen=(lambda: xpt_frame(me, side, src)) if me <= 4 and src <= 255 else None)
        elif action == "transition":
            t = str(data.get("type", "cut")).lower()
            if t not in ("cut", "autotrans", "auto"):
                raise ValueError(f"unknown transition '{t}'")
            tme = _int(data.get("me", 0), 0, 3, "me") + 1      # 0-3: M/E1, M/E2, M/E3, PGM/PST
            if t == "cut":
                label, frame, why = f"CUT {me_name(tme)}", transition_frame("cut", tme), None
            else:
                label, frame, why = f"AUTO TRANS {me_name(tme)}", transition_frame("auto", tme), None
        elif action == "macro":
            n = _int(data.get("macro", 1), 1, 65536, "macro")
            label, frame, why = f"macro register {n}", macro_frame(n), None
        elif action == "key":
            k = _int(data.get("keyer", 1), 1, 8, "keyer")
            on = bool(data.get("state"))
            kme = _int(data.get("me", 0), 0, 7, "me") + 1
            label, frame, why = bridge.lookup(
                f"key{k}:{'on' if on else 'off'}", f"keyer {k} {'ON' if on else 'OFF'}", "keyers 1-8 / ME1-4 only",
                gen=(lambda: key_frame(k, on, kme)) if kme <= 4 else None)
        elif action == "keyxpt":
            k = _int(data.get("keyer", 1), 1, 8, "keyer")
            src = _int(data.get("source", 1), 1, 255, "source")
            kme = _int(data.get("me", 0), 0, 7, "me") + 1
            label, frame, why = bridge.lookup(
                f"xpt:key{k}:{src}", f"keyer {k} fill/key source {src}", "ME1-4 only",
                gen=(lambda: key_source_frame(k, src, kme)) if kme <= 4 else None)
        elif action == "status":
            sme = _int(data.get("me", 0), 0, 7, "me") + 1
            ok, msg, snap = await asyncio.to_thread(bridge.read_status, sme)
            reply = {"status": "success" if ok else "error", "action": "status", "message": msg}
            if snap is not None:
                reply["data"] = snap
            return reply
        elif mtype == "SET_CONFIG":
            cfg = data.get("config") or {}
            bridge.set_target(str(cfg["ip"]), _int(cfg["port"], 1, 65535, "port"))
            bridge.suite = _int(cfg.get("suite", 1), 1, 4, "suite")
            return {"status": "success", "action": "set_config",
                    "message": f"Target {bridge.host}:{bridge.port} ({'LIVE' if bridge.live else 'DRY-RUN'})"}
        elif mtype == "TEST_CONNECTION":
            ok, msg = await asyncio.to_thread(
                bridge.probe, str(data["ip"]), _int(data["port"], 1, 65535, "port"))
            return {"status": "success" if ok else "error", "action": "test", "message": msg}
        else:
            return {"status": "error", "message": f"Unknown message: {raw[:80]}"}
    except (KeyError, ValueError, TypeError) as e:
        return {"status": "error", "action": action, "message": str(e)}

    ok, msg = await asyncio.to_thread(bridge.command, label, frame, why)
    return {"status": "success" if ok else "error", "action": action, "message": msg}


async def serve(args):
    import websockets  # imported here so the rest is testable without it

    bridge = GVGCPLBridge(args.ip, args.port, live=args.live, panel_name=args.panel_name)
    bridge.tally_port, bridge.suite = args.tally_port, args.suite
    import os
    bridge.captures = load_captures(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpl_captures.json"))
    logging.info(f"Loaded {len(bridge.captures)} captured frame(s) + macro/auto-trans encoders")
    n_req = sum(k.startswith("status:request") for k in bridge.captures)
    logging.info(f"Status read: {n_req} request frame(s) configured"
                 + ("" if n_req else " (none; relying on whatever the frame pushes after Connect)"))

    async def ws_handler(websocket, *_):
        logging.info("[WEBSOCKET] NT client connected")
        tasks = set()

        async def reply(message):
            try:
                await websocket.send(json.dumps(await handle_message(message, bridge)))
            except websockets.exceptions.ConnectionClosed:
                pass

        try:
            async for message in websocket:
                if _is_status(message):   # slow (opens the tally link): never block commands behind it
                    t = asyncio.create_task(reply(message))
                    tasks.add(t)
                    t.add_done_callback(tasks.discard)
                else:
                    await reply(message)
        except websockets.exceptions.ConnectionClosed:
            pass
        logging.info("[WEBSOCKET] NT client disconnected")

    mode = "LIVE (real CPL session; sends macro, auto-trans and captured frames)" if args.live else "DRY-RUN (no frame traffic)"
    logging.info(f"Mode: {mode}; target {args.ip}:{args.port}; panel name '{args.panel_name}'")
    if args.live:
        await asyncio.to_thread(bridge.connect)
    async with websockets.serve(ws_handler, args.ws_host, args.ws_port, origins=ALLOWED_ORIGINS):
        logging.info(f"Listening on ws://{args.ws_host}:{args.ws_port}")
        await asyncio.Future()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="NT GVG CPL bridge")
    ap.add_argument("--ip", default="10.1.32.10")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--tally-port", type=int, default=TALLY_PORT, help="frame Ethernet Tally port used for the status read")
    ap.add_argument("--suite", type=int, choices=[1, 2, 3, 4], default=1, help="suite used for the tally status read")
    ap.add_argument("--panel-name", default="NT", help="name sent in the CPL Connect request")
    ap.add_argument("--ws-host", default="localhost")
    ap.add_argument("--ws-port", type=int, default=8765)
    ap.add_argument("--live", action="store_true", help="open a real CPL session with the K-Frame")
    try:
        asyncio.run(serve(ap.parse_args()))
    except KeyboardInterrupt:
        logging.info("Bridge stopped by user.")
