# QualiaTransport

The channels that move a short run of bytes between two devices: **QR codes** (split across
several codes when one is not enough, including reading them back from an image) and the
**LAN** (find each other on the same segment, then hand the bytes over).

It is an independently reusable library: any project that needs "let two devices exchange a
small run of bytes" can use it without accepting Qualia2FA's vault format, account model or
sync protocol.

中文版见 [README.md](README.md).

```rust
use qualia_transport::qr::{EcLevel, QrProfile};

// Declare what this channel can do: EC level M, up to version 20 (97×97 modules).
let profile = QrProfile::new(EcLevel::Medium, 20)?;

// One code is enough if it fits; otherwise the payload is split into frames, and the user
// is asked to scan at most six. A payload that does not fit fails **here** (with the bytes
// needed and the limit), not after the user started scanning.
let symbols = profile.encode_payload_frames(payload, 6)?;
println!("{} codes to scan this time", symbols.len());

// The host draws the matrix from modules(); render() produces pixels.
let image = symbols[0].render(4, 4)?;

// The other direction: read **one frame** back from a camera or an imported image and feed
// the frames to the reassembler.
let frame = qualia_transport::qr::scan::decode_frame(&image)?;
let mut reassembler = qualia_transport::frame::Reassembler::from_first_frame();
if let Some(payload) = reassembler.accept(frame)? {
    // Complete.
}
```

The LAN half (multicast discovery needs no extra feature):

```rust
use qualia_transport::lan::lobby::Lobby;
use qualia_transport::lan::{LanAddress, LanAddressScanner};
use qualia_transport::qr::{EcLevel, QrProfile};

// Open the lobby: periodically announce "I am here, this is my endpoint key and port" into
// a multicast group, and listen to the others.
let mut lobby = Lobby::open(my_device_id, my_endpoint_key, my_port)?;

// The UI drains the queued events on every refresh.
while let Some(event) = lobby.try_poll() {
    // Each entry carries the address its announcement came from, so a peer that was
    // discovered can be dialed without asking again where it is.
    println!("{:?} is now {:?} at {:?}", event.peer.device, event.peer.status, event.peer.source);
}

// Across segments, where multicast does not reach, carry the connection info in a QR code
// instead. The record holds the endpoint key and the port and **no address**: dialing also
// needs an IP, and only the party that received a datagram from the peer has one (that is
// `event.peer.source` above), so what travels out of band is who to look for.
let address = LanAddress::new(my_endpoint_key, my_port);

// Displaying side: the record is a 42-byte payload like any other, so the QR half renders
// it — capacity check and splitting included — and all the caller states is how many codes
// the user is willing to scan.
let profile = QrProfile::new(EcLevel::Low, 10)?;
let symbols = address.to_qr_symbols(&profile, 4)?;

// Scanning side: feed in every piece of text the camera reads. Any order, the same code
// twice, both are fine; the call that completes the record returns it.
let mut scanner = LanAddressScanner::new();
if let Some(address) = scanner.push(scanned_text)? {
    // Dial it — the endpoint key and the port come from here.
}
```

## The four problems it solves

**1. The capacity has to be known before it is used.** A QR code that does not fit simply
does not fit; there is no retry, and finding out while the user is already holding up a
phone is the worst possible moment. The library therefore reports the **exact limit** of a
channel, and that number is **binary-searched against the encoder at run time** rather than
copied from a table in the specification: a transcription error does not fail to compile,
and the copied table starts drifting from real behaviour as soon as the encoder changes.
The error for an oversized payload carries `needed` and `limit`, which is what lets a
caller tell the user how far off it is and steer them to another channel.

**2. When one code is not enough, split instead of giving up.** The frame index and count
were **in the text envelope from the first version** (`Q2FA1:<index>/<count>:<BASE32>`), so
multi-frame introduced no new wire format: it is the first thing that actually produces
`1/3`, `2/3`, `3/3`. The scanning side knows which codes are still missing **without
decoding any of them**, and the reassembler accepts **any order** and repeated scans. This
path needs no network infrastructure at all, which makes it the only one left when there is
no WiFi and multicast is blocked.

**3. A platform camera hands back text, not bytes.** Android's ML Kit, iOS's AVFoundation,
the clipboard, and a string copied by eye can all carry text only. The payload therefore
goes through a text envelope (`Q2FA1:<index>/<count>:<BASE32>`) and is then encoded in the
QR code's **alphanumeric mode**: the whole string stays inside the 45-character table, at a
cost of about 10% of the capacity, and in exchange every scanner reads the same string.
Base32 rather than Base64 is chosen for exactly this reason — Base64's lower case letters
are not in that table.

**4. "Who is around" on a LAN should not require a scan every time.** Devices on the same
WiFi are already in one broadcast domain, so the LAN half does discovery over **UDP
multicast**: each device periodically announces its device id, endpoint public key and
port, and everyone accumulates a list of who is on the segment. Discovery is
**unauthenticated** — an announcement is a hint, and the real identity is proven by the
handshake when a connection is established (see below). Across segments, or where multicast
is blocked, the fallback is to carry the connection info out of band in a QR code.

## The three multi-frame numbers, not to be confused

All three are in **payload bytes** and cover different scopes:

| Method | Meaning |
|--------|---------|
| `QrProfile::payload_capacity()` | How much **one** code holds (single frame, shortest header) |
| `QrProfile::frame_payload_capacity()` | How much **each** code holds when split (computed against the longest header) |
| `QrProfile::exchange_capacity(n)` | How much one exchange (at most n codes) holds together |

The first two are not equal and cannot be used interchangeably: the header sits at the start
of the envelope and grows with the **number of digits** of the frame count (two digits add 2
characters, three add 4), while `payload_capacity` is exactly the point where one more
character no longer fits — splitting with it produces frames that cannot be rendered for a
payload that needs ten codes or more. `encode_payload_frames` picks the correct capacity
itself; the caller only states how many codes the user is willing to scan.
`exchange_capacity` is the number **declared to the layer above**: the place that decides
whether a payload can go by QR code uses it, rendering uses it, and both must be the same
number.

## Two contracts of the LAN channel

**Discovery may be unauthenticated; credentials must come from the channel.** A multicast
group is shared media: any machine on the segment can inject arbitrary bytes, including a
forged "I am device X" announcement. Announcements are therefore **not signed**; they only
answer "who is probably on this segment and where do I reach them". "Is that really that
device" is answered by the handshake when the connection is established, and "should this
payload be accepted" is answered by the layer above through an allow list keyed by device
id. Signing every announcement would wake the hardware keystore once per announce interval
and gain nothing: a forged announcement only makes the receiver open a connection that
cannot complete.

**The wire format carries the sender's device id.** The transport layer knows only the
endpoint public key (the one the handshake proves), while the layer above wants the device
id (the one the user sees). The mapping between them comes from unauthenticated
announcements and therefore **cannot be trusted**: every message carries the sender's own
device id, and the receiver checks it against the allow list it already has. The field does
not **establish** trust; it lets the receiver **apply** it.

## Using it in your own project

```toml
[dependencies]
qualia-transport = "0.1"
```

On mobile, where the platform camera is used and decoding from an image is not needed,
turning the default feature off drops the whole image decoding chain (which is also the only
`unsafe` in this library's dependency tree, coming from a caching crate):

```toml
[dependencies]
qualia-transport = { version = "0.1", default-features = false }
```

For the LAN data plane (QUIC transport), enable `iroh-lan`:

```toml
[dependencies]
qualia-transport = { version = "0.1", features = ["iroh-lan"] }
```

Multicast discovery and QR codes do **not** need that feature; it only brings in the QUIC
transport. Three things to know: it enlarges the dependency tree and the build time
noticeably; its minimum Rust version is **1.91** (required by iroh 1.3.0), above this
crate's 1.89; and **"no internet" currently goes only as far as "no relay, no DNS/pkarr
registration, HTTPS probing off" — packet-capture evidence is not done yet**, so do not
claim in public material that this channel is proven to stay offline.

## Interface contracts

- **Not fitting is an error, not an approximation.** An oversized payload returns an error;
  a code that is "almost big enough" is never produced.
- **The wire format is `Q2FA1:<index>/<count>:<BASE32>`.** The prefix makes somebody else's
  QR code recognisable at a glance (the report is "not this application's code" rather than
  "the payload is broken"); the frame index and count precede the payload, so the scanning
  side knows which codes are missing without decoding any of them. A single frame is written
  `1/1`, and the multi-frame path does not diverge from it.
- **Whatever can be encoded can be reassembled.** The splitting side emits an empty frame
  only for an empty payload, and the reassembler accepts an empty frame only when there is
  exactly one code — the two sides agree completely on which frame sets are legal. An empty
  frame inside a multi-frame set can only come from "the encoder cut once too often", and
  such a code would silently reassemble with extra zero bytes, so it is rejected.
- **The reassembler checks shape, never authenticity.** The "every frame except the last has
  the same length" rule catches user-level confusion (scanning A's first code and then B's
  second) and reports it as a dedicated error, instead of letting the user scan five codes
  and then read "decryption failed". **Real authentication is always the payload's AEAD
  layer**: the format has no "which payload do I belong to" field, so two payloads of
  identical shape are indistinguishable here — a deliberate boundary, not a defect.
- **The scanning side does not know the capacity and must not assume one.** How many bytes
  a code holds is a property of the **presenting screen** and is unavailable to the scanner;
  treating this device's own display capacity as an upper bound would reject legal frames
  from a larger screen. The scanning side therefore uses
  `Reassembler::from_first_frame()` and observes the full length from the first frame it
  receives.
- **One payload has exactly one text representation.** Case, padding and non-zero trailing
  bits are normalised or rejected — otherwise "are these two codes the same one" has no
  answer, and both deduplication and replay accounting depend on it.
- **The input is pixels, not an image file.** Decoding the image **format** belongs to the
  platform (`ImageIO` on the JVM, `BitmapFactory` on Android, `UIImage` on iOS): format
  decoders are a classic source of vulnerabilities, and this library only accepts pixels.
- **A panic inside the decoder does not take the process down either.** "Import an image
  somebody gave you" is the widest input surface this library has, and `rqrr` 0.11.0 has an
  `assert!` that a degenerate image triggers. Every call into it is wrapped in
  `catch_unwind`, and the panic becomes `Error::QrDecoderPanicked`. This is
  **containment, not a fix**: the fix belongs upstream, and it relies on panic unwinding —
  in a `panic = "abort"` build the layer does nothing.
- **A LAN announcement is a fixed 84-byte UDP datagram, and the connection info is a fixed
  42 bytes.** The fixed length gives the parser exactly one shape, "reject if the length is
  wrong", with no variable-length parsing that input could steer. The multicast TTL is
  fixed at 1: an announcement that drifts to another segment would make "a machine from the
  office next door shows up in the device list" a real, unexplainable symptom.
- **The connection info is an ordinary payload carried through the QR half's capacity and
  framing.** `LanAddress::to_qr_symbols` hands its 42 bytes to
  `QrProfile::encode_payload_frames`: one code if one is enough (from version 4 at level L
  it is), several frames if not. `LanAddress::to_qr_frame_texts` gives the texts of the same
  split, and `LanAddress::to_qr_text` / `from_qr_text` are the single-code form. The scanning
  side uses `LanAddressScanner` — a `Reassembler` plus the one step that parses the completed
  payload back into a record — so any order, repeated scans and an unknown capacity behave
  exactly as they do for any other QR payload. The record that travels this way is
  **unauthenticated**: whoever shows the code decides which endpoint a scan dials, and the
  handshake on the connection that follows is what proves the peer.
- **Discovery runs on every candidate interface at once.** Whether anyone else is on an
  interface is a question about a **broadcast domain**, not about a route: on a machine with a
  VPN tunnel, a hypervisor bridge or a container network, picking one interface by route can
  join the group where nobody announces — hearing nobody, and reporting no failure. Each
  candidate therefore gets its own socket, and all of them join, send and listen; an interface
  that leads nowhere costs one datagram. **No interface is guessed, and none is excluded by
  name** — a bridge into a real segment is a real segment. `LanConfig::interface` pins one.
- **Both the list and the inbox are bounded.** A device id is public information, so any
  machine on the segment can invent unlimited "new devices" at 84 bytes each. The peer list
  is therefore bounded and evicts the least recently heard entries, and a full inbox drops
  the oldest — the bound is a security property, not performance tuning.
- **The recipient is explicit.** A directed send must not degrade into a broadcast: a
  payload meant for B only, ending up with C, is invisible to the user.
- **Pure logic, with one exception.** The QR half and the LAN wire format touch no file
  system, network, clock or environment variable; every input is a parameter. Only the
  multicast lobby opens a socket, starts a background thread and reads a clock, and the
  decisions there are kept to a minimum — all the reasoning lives in the pure layer, so a
  property such as "three devices converge on one list" can be verified inside one process
  with no network. `#![forbid(unsafe_code)]` holds throughout, and no input may cause a
  panic: the only way to fail is to return an error.
- **The library generates no key material.** QR encoding is deterministic, and the multicast
  lobby only reads the endpoint public key and port the caller supplied. Nonces and keys
  inside a payload are the caller's responsibility.

## Status

Implemented: the QR capacity model, encoding, rendering, the text envelope, animated QR
(splitting and reassembly), decoding from an image (`scan-image`, on by default); LAN UDP
multicast discovery and connection info, including the route that carries the connection info
out of band in a QR code; the LAN data plane (`iroh-lan`, off by default).

Not implemented: the per-platform local network permission flows — Android 17 (targetSdk
37+) needs `ACCESS_LOCAL_NETWORK` requested at run time, and iOS needs
`NSLocalNetworkUsageDescription` plus the multicast entitlement. Those belong to host
integration; this library does not do them.

## Contributing

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo clippy --all-targets --no-default-features -- -D warnings   # feature combinations too
cargo test --no-default-features --all-targets
cargo clippy --all-targets --features iroh-lan -- -D warnings     # LAN data plane
cargo test --features iroh-lan
cargo doc --no-deps            # no warnings (with RUSTDOCFLAGS="-D warnings")
cargo +1.89 check --all-targets
cargo deny check
```

The fuzz targets live in `fuzz/` (they need nightly and cargo-fuzz, and on Windows a
`PATH` fix first — see `fuzz/README.md`):

```bash
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run envelope_decode -- -max_total_time=60
cargo +nightly fuzz run frame_reassemble -- -max_total_time=60
cargo +nightly fuzz run qr_scan -- -max_total_time=60
cargo +nightly fuzz run lan_datagram -- -max_total_time=60
```

### MSRV policy

The minimum supported Rust version is **1.89**, but "every feature combination holds on
1.89" is **not** true: `iroh-lan` requires **1.91** (the `rust-version` iroh 1.3.0
declares). CI's MSRV job therefore covers the two combinations without `iroh-lan`, and the
combination with it is covered by the stable toolchain. The MSRV moves with what the
dependencies actually need, and every move is verified in CI with a real toolchain.

## License

LGPL-3.0-or-later; see [LICENSE](LICENSE) and [COPYING.LESSER](COPYING.LESSER).

LGPL rather than MIT/Apache is deliberate: this library parses attacker-controlled input
(scanned text, imported images, datagrams from anyone on the segment), so any modification
should come back as source that can be audited.
