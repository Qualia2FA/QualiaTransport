// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! LAN **lobby**: see each other on one network segment and exchange "where to
//! reach me".
//!
//! # What it does
//!
//! Periodically announces "I am here, my endpoint key and port are these" into a
//! multicast group, and listens for the announcements of others. What arrives
//! accumulates into a [`LanView`]: who is on this segment.
//!
//! It does **not** carry synchronization payloads. Payloads travel another way (a
//! QUIC connection, see the crate root, or an out-of-band QR code) and the lobby
//! only finds peers. Multicast is unreliable and any device on the segment can
//! inject into it, so the worst case here is a phantom peer in the view, never a
//! payload that has to be parsed.
//!
//! # The only module in this crate that touches I/O
//!
//! It opens sockets, spawns a thread and reads the clock, so its logic is kept
//! minimal: **all decisions live in [`LanView`]**, and this module only moves
//! bytes in and out and announces on schedule. The clock is used for intervals
//! and leases only; it never enters the protocol, which carries no timestamps and
//! therefore works even when two devices disagree about the time of day.
//!
//! # Events
//!
//! The worker thread reports what happened over an unbounded `mpsc` queue of
//! [`Event`]s, each tagged with the instant it happened. That queue is the only
//! link between the worker's view and the caller's view: the worker never blocks
//! on the caller, and a poll returns `None` rather than waiting.
//!
//! # Bounds
//!
//! The view keeps at most [`LanView::MAX_PEERS`] (1024) peers. A device announces
//! every [`ANNOUNCE_INTERVAL_MS`] (30 s) by default, so discovery takes at most
//! that long, and a peer silent for [`LanView::STALE_AFTER_MS`] (3 min, six
//! announce periods) expires and is reported as [`EventKind::Expired`].
//!
//! # Platform notes
//!
//! - **Android 17 (targetSdk 37+)** needs `ACCESS_LOCAL_NETWORK` to send and
//!   receive multicast on the local network; the platform layer requests it.
//! - **Multiple interfaces**: every candidate of [`candidate_interfaces`] gets its own socket,
//!   all of them join the group and announcements leave by all of them. Discovery is scoped to a
//!   segment, so a host that follows a single route can end up joined where no other device
//!   announces: it hears nobody, and nothing reports a failure. A caller that knows better
//!   sets [`LanConfig::interface`] to pin one interface instead of taking every candidate.

//! - **Windows** delivers an incoming multicast datagram only to the last socket
//!   that bound the group and port, so two [`Lobby`] instances on one machine do
//!   not hear each other there. That is IP multicast semantics, not a defect.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use qualia_dik::DeviceId;
use socket2::{Domain, Protocol, Socket, Type};

use super::wire::{Announcement, EndpointKey, Kind, LanView, Peer};
use crate::error::{Error, Result};

/// The multicast group used by the lobby.
///
/// `239.255.81.65` lies inside the administratively scoped range `239.0.0.0/8`
/// (RFC 2365) and inside its organization-local subrange `239.255.0.0/16`, so it
/// does not collide with well-known groups such as SSDP (`239.255.255.250`) or
/// mDNS (`224.0.0.251`).
///
/// `0x51` is `Q` and `65` is `A`; the digits carry no protocol meaning, they only
/// make the address recognizable in a packet capture.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 81, 65);

/// The UDP port used by the lobby.
///
/// It sits outside the dynamic/private range (49152–65535), which RFC 6335
/// reserves for **ephemeral** ports: a long-lived multicast listener placed there
/// would collide with system-assigned ephemeral ports. This is a number in the
/// registered range (1024–49151) that no well-known service occupies.
pub const PORT: u16 = 21377;

/// How often a device announces, in milliseconds.
///
/// 30 s balances "how quickly two users see each other after opening the app"
/// against the cost of idling. It fixes two numbers: worst-case discovery latency
/// is 30 s, and [`LanView::STALE_AFTER_MS`] (3 min) is exactly six times it, so
/// six consecutive lost periods are needed to declare a peer offline.
pub const ANNOUNCE_INTERVAL_MS: u64 = 30_000;

/// How long to wait for a datagram before checking again whether it is time to
/// announce or to exit, in milliseconds.
///
/// This is not a protocol parameter, it only bounds **shutdown latency**:
/// `recv_from` blocks, so without this cap the worker thread would sleep until the
/// next multicast datagram (up to a full announce period) after the exit flag is
/// cleared. 200 ms balances an imperceptible shutdown against five wakeups per
/// second, and those wakeups are negligible on a thread that only sends and
/// receives multicast.
const LOOP_SLICE_MS: u64 = 200;

/// Configuration of the lobby.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanConfig {
    /// Multicast group address.
    pub group: Ipv4Addr,
    /// UDP port.
    pub port: u16,
    /// Announce interval in milliseconds.
    pub announce_interval_ms: u64,
    /// One local interface to use, or `None` for every candidate.
    ///
    /// `None` is what a caller wants: discovery is per broadcast domain, so every candidate of
    /// [`candidate_interfaces`] gets its own socket, all of them join the group, and
    /// announcements leave by all of them. `Some` pins one address for a caller that knows
    /// better — a user picking an interface in a settings screen, or a test.
    pub interface: Option<Ipv4Addr>,
}

impl Default for LanConfig {
    fn default() -> Self {
        Self {
            group: GROUP,
            port: PORT,
            announce_interval_ms: ANNOUNCE_INTERVAL_MS,
            interface: None,
        }
    }
}

impl LanConfig {
    /// The `(group, port)` pair announcements are sent to.
    #[must_use]
    pub const fn group_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.group, self.port)
    }
}

/// Every local address an announcement is sent from, and the group is joined on.
///
/// # Discovery is scoped to a segment, not to a route
///
/// A route answers "where does a datagram to that address leave"; discovery asks "who is on my
/// segment", and a segment is a property of an interface. A host with virtual adapters — a VPN
/// tunnel, a hypervisor bridge, a container network — gets a route that leads into one of them,
/// and a lobby that follows it joins the group where no other device announces: it hears
/// nobody, and nothing reports a failure. Measured on a Windows host whose operating system
/// joined the group on a VPN adapter while the device it was looking for was on WiFi, one
/// interface away.
///
/// Every candidate therefore gets its own socket. All of them join the group, announcements
/// leave by all of them, and whichever segment a peer is on is a segment that is covered.
/// Interfaces that lead nowhere cost one datagram each and stay silent, which is why nothing
/// is guessed and nothing is excluded by name: a bridge into a real segment **is** a real
/// segment.
///
/// A candidate is an IPv4 address that is neither loopback, nor link-local, nor the wildcard,
/// and whose netmask is wider than a single host.
#[must_use]
pub fn candidate_interfaces() -> Vec<Ipv4Addr> {
    let mut addresses: Vec<Ipv4Addr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|interface| match interface.addr {
            if_addrs::IfAddr::V4(address) => Some(address),
            if_addrs::IfAddr::V6(_) => None,
        })
        .filter(|address| {
            let ip = address.ip;
            !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()
        })
        .filter(|address| {
            address
                .netmask
                .octets()
                .iter()
                .map(|octet| octet.count_ones())
                .sum::<u32>()
                < 31
        })
        .map(|address| address.ip)
        .collect();

    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

/// Something that happened in the lobby.
///
/// An event describes what just changed, which a full view cannot express, and it
/// carries the whole [`Peer`] snapshot so that it is self-contained: the queue is
/// the only link between the worker's view and the caller's, and a receiver must
/// not have to ask anywhere else for a peer's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Which peer it is about, and his state at that moment.
    pub peer: Peer,
    /// What happened.
    pub kind: EventKind,
}

/// The kind of event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// The peer was first heard of, or came back.
    Appeared,
    /// He announced that he is leaving.
    SaidGoodbye,
    /// He has been silent for too long.
    Expired,
}

/// What the worker thread puts on the event queue: an event plus the instant it
/// happened.
///
/// The instant must travel with the event, because the caller's view records it as
/// [`Peer::last_seen_ms`]: stamping it from the caller's own clock would add
/// however long the event waited in the queue, which is exactly what would make
/// the two sides compute different lease outcomes.
#[derive(Debug, Clone, Copy)]
struct TimedEvent {
    /// The event itself.
    event: Event,
    /// When it happened, in milliseconds since the worker thread started.
    at_ms: u64,
}

/// The values this device announces about itself.
///
/// They always appear together — in announcements, in the goodbye and in the
/// worker's periodic announce — so they travel as one struct; passing them as
/// separate arguments invites dropping the port somewhere, whose symptom is a peer
/// that can be discovered but not connected to.
#[derive(Debug, Clone, Copy)]
struct SelfAnnouncement {
    /// This device's device identifier.
    device: DeviceId,
    /// This device's transport endpoint key.
    endpoint_key: EndpointKey,
    /// The port this device listens on.
    port: u16,
}

impl SelfAnnouncement {
    /// Builds an announcement addressed to other devices.
    fn announcement(&self, kind: Kind, sequence: u64) -> Announcement {
        Announcement {
            kind,
            sequence,
            device: self.device,
            endpoint_key: self.endpoint_key,
            port: self.port,
        }
    }
}

/// The LAN lobby.
///
/// # It spawns its own thread
///
/// Sending and receiving happen on one worker thread, so the caller neither feeds
/// it an event loop nor cleans anything up beyond dropping it. The thread exits
/// only on [`Lobby::shutdown`] or `Drop`, and on the way out it sends one `Bye` for
/// every peer still "here", so the other side sees the peer as closed immediately
/// instead of waiting for the 3-minute lease.
///
/// # A device receives its own announcements
///
/// `IP_MULTICAST_LOOP` is on, so a device hears its own announcement back. That is
/// **normal**: the "a sequence that does not increase is an old message" rule in
/// [`LanView::observe`] drops it, and the worker also drops datagrams whose
/// `device == me`.
pub struct Lobby {
    /// The values this device announces about itself.
    me: SelfAnnouncement,
    /// One socket per candidate interface, shared by sending and receiving.
    ///
    /// Several rather than one: an announcement has to leave by the interface whose segment
    /// the peer is on, and that cannot be known before the peer answers (see
    /// [`candidate_interfaces`]).
    sockets: Arc<Vec<Arc<UdpSocket>>>,
    /// Configuration.
    config: LanConfig,
    /// Peers currently seen (the `Lobby`-side copy).
    view: LanView,
    /// Receiving end of the event queue.
    events: Receiver<TimedEvent>,
    /// Handle of the worker thread.
    worker: Option<JoinHandle<()>>,
    /// Flag that tells the worker thread to exit.
    running: Arc<AtomicBool>,
    /// Announcement sequence number.
    ///
    /// **Shared with the worker thread**, hence an `Arc<AtomicU64>` rather than a
    /// plain field: `announce_now` (caller thread) and the periodic announce
    /// (worker thread) both advance it, and two separate counters would silently
    /// break the "sequences are unique and increasing" premise — the lobby would
    /// then occasionally treat a genuinely new announcement as an old one.
    sequence: Arc<AtomicU64>,
}

impl Lobby {
    /// Opens the lobby: binds the port, joins the multicast group and starts
    /// announcing.
    ///
    /// `endpoint_key` and `port` say how others reach this device and come from
    /// the transport layer; the lobby knows nothing about QUIC, it only repeats
    /// those two values.
    ///
    /// # Errors
    ///
    /// [`Error::LanSocket`] if binding or joining the group fails. The usual
    /// causes are a **port already in use** (two instances on one machine) and a
    /// **firewall or system policy** that forbids joining the group.
    pub fn open(me: DeviceId, endpoint_key: EndpointKey, port: u16) -> Result<Self> {
        Self::open_with(me, endpoint_key, port, LanConfig::default())
    }

    /// Opens the lobby with the given configuration.
    ///
    /// # Errors
    ///
    /// Same as [`Lobby::open`].
    pub fn open_with(
        me: DeviceId,
        endpoint_key: EndpointKey,
        port: u16,
        config: LanConfig,
    ) -> Result<Self> {
        let me = SelfAnnouncement {
            device: me,
            endpoint_key,
            port,
        };
        let sockets = Arc::new(bind_multicast(config)?);
        let (sender, events) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let sequence = Arc::new(AtomicU64::new(0));

        let worker = {
            let sockets = Arc::clone(&sockets);
            let running = Arc::clone(&running);
            let sequence = Arc::clone(&sequence);
            thread::Builder::new()
                .name("qualia-lan-lobby".into())
                .spawn(move || {
                    let mut view = LanView::new();
                    serve(
                        sockets.as_slice(),
                        config,
                        me,
                        &mut view,
                        &sender,
                        &running,
                        &sequence,
                    );
                })
                .map_err(|_| Error::LanSocket { operation: "spawn" })?
        };

        Ok(Self {
            me,
            sockets,
            config,
            view: LanView::new(),
            events,
            worker: Some(worker),
            running,
            sequence,
        })
    }

    /// Peers currently seen (only those considered "here").
    #[must_use]
    pub fn view(&self) -> &LanView {
        &self.view
    }

    /// Takes one event without blocking.
    ///
    /// Returns `None` when nothing is queued; that is **not** an error. A UI
    /// refresh drains everything that piled up, so there is deliberately no
    /// "block until the next event", which would tie the caller to network
    /// traffic.
    pub fn try_poll(&mut self) -> Option<Event> {
        self.events.try_recv().ok().map(|timed| self.apply(timed))
    }

    /// Takes one event, blocking for at most `timeout`.
    ///
    /// Returns `None` on timeout, which means the same thing as "no event": the
    /// caller either waits again or does something else.
    pub fn poll(&mut self, timeout: Duration) -> Option<Event> {
        self.events
            .recv_timeout(timeout)
            .ok()
            .map(|timed| self.apply(timed))
    }

    /// Announces immediately, without waiting for the next period.
    ///
    /// Meant for the moment a user opens the sync screen: otherwise the next
    /// period is up to 30 s away.
    ///
    /// # Errors
    ///
    /// [`Error::LanSocket`] if sending fails (interface gone, multicast blocked by
    /// policy).
    pub fn announce_now(&self) -> Result<()> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let announcement = self.me.announcement(Kind::Hello, sequence);
        send_datagram(&self.sockets, self.config, &announcement)
    }

    /// Closes the lobby: sends a `Bye` for every peer still here, then stops the
    /// worker thread.
    ///
    /// Calling it more than once is safe; the second call does nothing.
    pub fn shutdown(&mut self) {
        self.send_goodbye();
        self.running.store(false, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    /// Records an event in this side's view.
    ///
    /// Both views are written through the same path, so replaying an event here is what keeps
    /// the worker's view and this one consistent, and the sequence rule makes applying the same
    /// event twice idempotent. The address travels with the event as well: a peer this side's
    /// view can show must be one it can also dial.
    fn apply(&mut self, timed: TimedEvent) -> Event {
        let kind = match timed.event.kind {
            EventKind::Appeared => Kind::Hello,
            EventKind::SaidGoodbye | EventKind::Expired => Kind::Bye,
        };
        let peer = timed.event.peer;
        self.view.observe_from(
            Announcement {
                kind,
                sequence: peer.sequence,
                device: peer.device,
                endpoint_key: peer.endpoint_key,
                port: peer.port,
            },
            peer.source,
            timed.at_ms,
        );
        timed.event
    }

    /// Sends a `Bye` for every peer still "here".
    fn send_goodbye(&self) {
        for peer in self.view.here() {
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
            let announcement = self.me.announcement(Kind::Bye, sequence);
            let _ = send_datagram(&self.sockets, self.config, &announcement);
            let _ = peer;
        }
    }
}

impl Drop for Lobby {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Worker thread: listens and announces on schedule.
///
/// It is a free function rather than a method so that it can own the mutable view:
/// [`Lobby::view`] is a separate read-only copy for the caller, not the same data.
/// The two are synchronized by the event queue alone, so the caller is never
/// blocked by the network thread.
///
/// A `recv_from` error that is neither `WouldBlock` nor `TimedOut` is not fatal:
/// the loop sleeps for one [`LOOP_SLICE_MS`] slice and tries again, and only
/// `running` becoming `false` ends it. A failed `events.send` means the receiver is
/// gone (the `Lobby` is being dropped) and is ignored as well.
fn serve(
    sockets: &[Arc<UdpSocket>],
    config: LanConfig,
    me: SelfAnnouncement,
    view: &mut LanView,
    events: &Sender<TimedEvent>,
    running: &AtomicBool,
    sequence: &AtomicU64,
) {
    let started = Instant::now();
    let mut last_announce: Option<Instant> = None;
    let mut buffer = [0_u8; 512];

    while running.load(Ordering::Relaxed) {
        // 1. Time to announce.
        let due = match last_announce {
            None => true,
            Some(last) => last.elapsed().as_millis() as u64 >= config.announce_interval_ms,
        };
        if due {
            let sequence = sequence.fetch_add(1, Ordering::Relaxed);
            let _ = send_datagram(sockets, config, &me.announcement(Kind::Hello, sequence));
            last_announce = Some(Instant::now());
        }

        // 2. Listen for a while.
        let slice = match last_announce {
            Some(last) => config
                .announce_interval_ms
                .saturating_sub(last.elapsed().as_millis() as u64)
                .clamp(1, LOOP_SLICE_MS),
            None => LOOP_SLICE_MS,
        };
        let per_socket = (slice / sockets.len().max(1) as u64).max(1);

        for socket in sockets {
            let _ = socket.set_read_timeout(Some(Duration::from_millis(per_socket)));

            match socket.recv_from(&mut buffer) {
                Ok((length, from)) => {
                    if let Some(datagram) = buffer.get(..length)
                        && let Ok(announcement) = Announcement::decode(datagram)
                        && announcement.device != me.device
                    {
                        let at_ms = started.elapsed().as_millis() as u64;
                        let changed = view.observe_from(announcement, Some(from), at_ms);
                        if changed && let Some(peer) = view.get(&announcement.device) {
                            let kind = match announcement.kind {
                                Kind::Hello => EventKind::Appeared,
                                Kind::Bye => EventKind::SaidGoodbye,
                            };
                            let _ = events.send(TimedEvent {
                                event: Event { peer, kind },
                                at_ms,
                            });
                        }
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => thread::sleep(Duration::from_millis(LOOP_SLICE_MS)),
            }
        }

        // 3. Leases.
        let at_ms = started.elapsed().as_millis() as u64;
        for device in view.expire(at_ms) {
            if let Some(peer) = view.get(&device) {
                let _ = events.send(TimedEvent {
                    event: Event {
                        peer,
                        kind: EventKind::Expired,
                    },
                    at_ms,
                });
            }
        }
    }
}

/// Binds one socket per candidate interface and joins the multicast group.
///
/// # Socket options
///
/// `SO_REUSEADDR` **must** be set before `bind`: without it a second process on the
/// same machine either fails to bind (Windows) or receives no multicast at all
/// (Linux). `IP_MULTICAST_TTL` is fixed at 1 so announcements stay on this segment,
/// and `IP_MULTICAST_LOOP` is left enabled, which same-machine tests rely on. `std`'s
/// `UdpSocket::bind` sets no options, and `setsockopt` is `unsafe` while this crate
/// has `#![forbid(unsafe_code)]`, so all of it goes through `socket2` before the
/// socket is handed to `UdpSocket::from`.
///
/// # The bound address is per platform
///
/// On Linux and the BSDs — Android included — a socket receives a datagram only when
/// the datagram's destination address equals the address the socket is bound to. A
/// multicast datagram is addressed to the **group**, so a socket bound to one
/// interface's unicast address matches nothing and receives no announcement at all,
/// silently: hearing nobody is also what a quiet segment looks like. Those platforms
/// therefore bind the wildcard, and the per-interface `join_multicast_v4` plus
/// `IP_MULTICAST_IF` are what keep the sockets apart and their announcements leaving
/// by the interface they belong to.
///
/// Windows delivers multicast by group membership rather than by bound address, so
/// binding the interface address there is what keeps several sockets on one port
/// apart.
///
/// # Cost of the wildcard bind
///
/// Unicast datagrams sent to this port are received as well. That is acceptable:
/// [`Announcement::decode`] checks the magic first and drops anything that is not
/// ours.
fn bind_multicast(config: LanConfig) -> Result<Vec<Arc<UdpSocket>>> {
    let addresses = match config.interface {
        Some(address) => vec![address],
        None => candidate_interfaces(),
    };

    let mut bound = Vec::new();
    for address in addresses {
        if let Ok(socket) = bind_one(config, address) {
            bound.push(Arc::new(socket));
        }
    }

    if bound.is_empty() {
        bound.push(Arc::new(bind_one(config, Ipv4Addr::UNSPECIFIED)?));
    }

    Ok(bound)
}

/// Binds one socket to [bind_address], joins the group on `address`, and sends multicast from it.
///
/// The join is what decides which interface's traffic reaches this socket; the bound address is
/// the wildcard wherever the platform filters by destination address (see [`bind_multicast`]).
fn bind_one(config: LanConfig, address: Ipv4Addr) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| Error::LanSocket { operation: "new" })?;

    socket
        .set_reuse_address(true)
        .map_err(|_| Error::LanSocket {
            operation: "set_reuse_address",
        })?;

    let bind_addr = SocketAddr::V4(SocketAddrV4::new(bind_address(address), config.port));
    socket
        .bind(&bind_addr.into())
        .map_err(|_| Error::LanSocket { operation: "bind" })?;

    socket
        .join_multicast_v4(&config.group, &address)
        .map_err(|_| Error::LanSocket {
            operation: "join_multicast",
        })?;

    if !address.is_unspecified() {
        socket
            .set_multicast_if_v4(&address)
            .map_err(|_| Error::LanSocket {
                operation: "set_multicast_if",
            })?;
    }

    socket
        .set_multicast_loop_v4(true)
        .map_err(|_| Error::LanSocket {
            operation: "set_multicast_loop",
        })?;

    socket
        .set_multicast_ttl_v4(1)
        .map_err(|_| Error::LanSocket {
            operation: "set_multicast_ttl",
        })?;

    Ok(UdpSocket::from(socket))
}

/// The local address a multicast socket is bound to on this platform.
///
/// The wildcard everywhere the platform filters an incoming datagram by its destination
/// address: a multicast datagram names the group, so a socket bound to an interface's unicast
/// address receives nothing. Windows matches by group membership instead, and there the
/// interface address is what keeps several sockets on one port apart.
fn bind_address(interface: Ipv4Addr) -> Ipv4Addr {
    if cfg!(windows) {
        interface
    } else {
        Ipv4Addr::UNSPECIFIED
    }
}

/// Encodes an announcement and sends it to the configured group address.
fn send_datagram(
    sockets: &[Arc<UdpSocket>],
    config: LanConfig,
    announcement: &Announcement,
) -> Result<()> {
    let target = SocketAddr::V4(config.group_addr());
    let datagram = announcement.encode();
    let mut sent = 0_usize;
    let mut failure = None;

    for socket in sockets {
        match socket.send_to(&datagram, target) {
            Ok(_) => sent += 1,
            Err(error) => failure = Some(error),
        }
    }

    if sent == 0 {
        failure.map_or_else(
            || {
                Err(Error::LanSocket {
                    operation: "send_to",
                })
            },
            |_| {
                Err(Error::LanSocket {
                    operation: "send_to",
                })
            },
        )
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every candidate is an address this host can really send from**, and none of them is an
    /// address that cannot carry discovery.
    ///
    /// A host with no candidate at all (only a loopback interface) passes trivially: the lobby
    /// then falls back to letting the operating system choose.
    #[test]
    fn every_candidate_interface_is_an_address_of_this_host() {
        for address in candidate_interfaces() {
            assert!(
                !address.is_loopback(),
                "loopback is not a segment: {address}"
            );
            assert!(
                !address.is_link_local(),
                "link-local is not a segment: {address}"
            );
            assert!(
                !address.is_unspecified(),
                "the wildcard is not an interface"
            );
            assert!(
                std::net::UdpSocket::bind((address, 0)).is_ok(),
                "a candidate must be an address of this host, got {address}"
            );
        }
    }
    use crate::lan::wire::{DATAGRAM_LEN, PeerStatus};
    use socket2::SockAddr;
    use std::sync::Mutex;

    /// Whether multicast really works on this machine.
    ///
    /// Where there is no usable network stack (many CI containers, machines with
    /// networking turned off) no multicast is delivered, and that is an environment
    /// problem rather than a problem of this crate. Every test that needs a
    /// datagram to really arrive over multicast asks this first and returns early
    /// instead of failing.
    static MULTICAST_WORKS: Mutex<Option<bool>> = Mutex::new(None);

    /// Probes once and caches the result.
    fn multicast_works() -> bool {
        let mut cached = MULTICAST_WORKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(known) = *cached {
            return known;
        }
        let ok = probe_multicast();
        *cached = Some(ok);
        ok
    }

    /// Really builds a pair of sockets and tries once: one joins the group, the
    /// other sends into it, and the result says whether the datagram arrived.
    ///
    /// The receiver joins on the **loopback** interface and the sender pins its
    /// outgoing multicast interface to loopback as well; otherwise the datagram
    /// leaves by the default interface and a loopback-joined receiver never sees
    /// it, which is normal IP multicast semantics rather than a defect.
    ///
    /// Returns `false` when the machine cannot complete the exchange.
    fn probe_multicast() -> bool {
        let group = Ipv4Addr::new(239, 255, 81, 200);
        let Ok(listener) = joined_socket(group, 0, Ipv4Addr::LOCALHOST) else {
            return false;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("must set the read timeout");
        let Ok(port) = listener.local_addr().map(|addr| addr.port()) else {
            return false;
        };

        let Ok(sender) = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) else {
            return false;
        };
        if sender.set_multicast_if_v4(&Ipv4Addr::LOCALHOST).is_err() {
            return false;
        }
        let target = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(group, port)));
        if sender.send_to(&[0xAB; 16], &target).is_err() {
            return false;
        }

        let mut buffer = [0_u8; 64];
        matches!(listener.recv_from(&mut buffer), Ok((16, _)))
    }

    /// Builds a receiving socket that binds the wildcard address, sets
    /// `SO_REUSEADDR` and joins the group.
    ///
    /// The order matches [`bind_multicast`], but the interface is a parameter:
    /// tests use it to pin multicast to loopback, otherwise they would drift on a
    /// machine with no real interface or with several.
    fn joined_socket(
        group: Ipv4Addr,
        port: u16,
        interface: Ipv4Addr,
    ) -> std::io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).into())?;
        socket.join_multicast_v4(&group, &interface)?;
        socket.set_multicast_loop_v4(true)?;
        socket.set_multicast_ttl_v4(1)?;
        Ok(UdpSocket::from(socket))
    }

    /// Builds an endpoint key for tests.
    fn endpoint(seed: u8) -> EndpointKey {
        EndpointKey::from_bytes([seed; 32])
    }

    /// A lobby configuration for tests.
    ///
    /// `port` **must not** be 0: announcements are sent to `(group, port)`, and port
    /// 0 would make "where we send" and "where we bind" two different ephemeral
    /// ports, so nobody would hear anybody. Every test uses a distinct `group`, so
    /// tests running concurrently do not interfere.
    ///
    /// The interface is left to [`default_interface`], the same as a real caller: a test that
    /// pinned one would stop exercising the choice that a multi-adapter host gets wrong.
    fn config(last_octet: u8, port: u16, announce_interval_ms: u64) -> LanConfig {
        LanConfig {
            group: Ipv4Addr::new(239, 255, 81, last_octet),
            port,
            announce_interval_ms,
            interface: None,
        }
    }

    /// **Multicast really round-trips over real sockets.**
    ///
    /// This cannot use [`Lobby`] itself: on Windows a group and port can be bound
    /// only once and the last binder wins, so two `Lobby` instances on one machine
    /// do not hear each other. The test builds the socket pair explicitly — one
    /// joins the group, one sends into it — pinning down that joining a group really
    /// makes datagrams arrive. It covers `join_multicast_v4` and `send_to`, the two
    /// places in this module that make system calls; view merging is covered by the
    /// pure-logic tests in `wire`.
    ///
    /// Returns early when the machine has no usable network stack.
    #[test]
    fn multicast_round_trip_over_the_loopback_interface() {
        let group = Ipv4Addr::new(239, 255, 81, 67);
        let Ok(listener) = joined_socket(group, 0, Ipv4Addr::LOCALHOST) else {
            return;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("must set the read timeout");
        let port = listener
            .local_addr()
            .expect("must have a local address")
            .port();

        let sender = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .expect("must build the sender");
        if sender.set_multicast_if_v4(&Ipv4Addr::LOCALHOST).is_err() {
            return;
        }

        let announcement = Announcement {
            kind: Kind::Hello,
            sequence: 1,
            device: DeviceId::from_bytes([7; 32]),
            endpoint_key: endpoint(7),
            port: 41_000,
        };
        let target = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(group, port)));
        sender
            .send_to(&announcement.encode(), &target)
            .expect("must send the multicast");

        let mut buffer = [0_u8; 512];
        let (length, _) = listener
            .recv_from(&mut buffer)
            .expect("must receive the multicast");
        let decoded =
            Announcement::decode(&buffer[..length]).expect("a self-sent datagram must decode");
        assert_eq!(decoded, announcement);
    }

    /// The "bind + join group + set TTL" path runs to completion.
    ///
    /// On a machine without networking `join_multicast_v4` fails instead; the error
    /// must then come from one of the system calls in that path.
    #[test]
    fn binding_and_joining_works_on_this_machine() {
        let config = config(68, 21_392, ANNOUNCE_INTERVAL_MS);
        match bind_multicast(config) {
            Ok(socket) => {
                assert_eq!(
                    socket[0]
                        .local_addr()
                        .expect("must have a local address")
                        .port(),
                    config.port,
                    "it binds the port from the configuration"
                );
            }
            Err(Error::LanSocket { operation }) => {
                assert!(
                    matches!(
                        operation,
                        "new" | "set_reuse_address" | "bind" | "join_multicast"
                    ),
                    "only these system calls can fail, got {operation}"
                );
            }
            Err(other) => panic!("impossible error: {other:?}"),
        }
    }

    /// **Where the platform filters by destination address, the receiving socket is bound to the
    /// wildcard.**
    ///
    /// A multicast datagram is addressed to the group, so a socket bound to one interface's
    /// unicast address matches nothing and receives no announcement at all — silently, because a
    /// segment where nobody announces looks exactly the same. This pins the bound address that
    /// makes receiving possible on Linux, the BSDs and Android.
    #[cfg(not(windows))]
    #[test]
    fn a_receiving_socket_is_bound_to_the_wildcard() {
        let socket = bind_one(config(72, 0, ANNOUNCE_INTERVAL_MS), Ipv4Addr::LOCALHOST)
            .expect("must bind the socket");
        assert_eq!(
            socket
                .local_addr()
                .expect("must have a local address")
                .ip(),
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "a socket that must hear the group has to be bound to the wildcard"
        );
    }

    /// **Two sockets really see each other on one group and port.**
    ///
    /// This is as far as verification goes on a single machine: Windows hands a
    /// datagram only to the last binder, so two `Lobby` instances do **not** hear
    /// each other there (IP multicast semantics, not a defect). The test therefore
    /// splits out the real half: an external socket joins the group first, then
    /// [`bind_multicast`] — the very function `Lobby` uses — joins the same group,
    /// and one announcement is really sent into it, after which each side is checked
    /// for what it received. The sender joins the group too, otherwise its multicast
    /// might not be delivered to the joined members on this segment.
    ///
    /// Received datagrams are compared against the announcement; when neither side
    /// received anything, multicast is unavailable on this machine and the test
    /// returns early.
    #[test]
    fn two_sockets_can_join_the_same_group() {
        let config = config(69, 21_393, ANNOUNCE_INTERVAL_MS);

        let Ok(external) = joined_socket(config.group, config.port, Ipv4Addr::UNSPECIFIED) else {
            return;
        };
        external
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("must set the read timeout");

        let Ok(lobby_socket) = bind_multicast(config) else {
            return;
        };
        lobby_socket[0]
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("must set the read timeout");

        let Ok(sender) = joined_socket(config.group, 0, Ipv4Addr::UNSPECIFIED) else {
            return;
        };
        let announcement = Announcement {
            kind: Kind::Hello,
            sequence: 1,
            device: DeviceId::from_bytes([9; 32]),
            endpoint_key: endpoint(9),
            port: 41_009,
        };
        let target = SocketAddr::V4(config.group_addr());
        if sender.send_to(&announcement.encode(), target).is_err() {
            return;
        }

        let mut buffer = [0_u8; 512];
        let mut seen = Vec::new();
        for socket in [&external, &lobby_socket[0]] {
            if let Ok((length, _)) = socket.recv_from(&mut buffer)
                && let Ok(decoded) = Announcement::decode(&buffer[..length])
            {
                seen.push(decoded);
            }
        }

        if seen.is_empty() {
            return;
        }
        for decoded in seen {
            assert_eq!(decoded, announcement);
        }
    }

    /// The datagram length equals the wire format length and the magic is present.
    ///
    /// This pins [`crate::lan::wire::DATAGRAM_LEN`], the constant summed from the
    /// field lengths: if it drifts from the fields, this test fails first.
    #[test]
    fn the_datagram_length_matches_the_wire_format() {
        let announcement = Announcement {
            kind: Kind::Bye,
            sequence: 0,
            device: DeviceId::from_bytes([0; 32]),
            endpoint_key: endpoint(0),
            port: 0,
        };
        let bytes = announcement.encode();
        assert_eq!(
            bytes.len(),
            DATAGRAM_LEN,
            "magic 8 + version 1 + kind 1 + sequence 8 + device 32 + endpoint key 32 + port 2"
        );
        assert_eq!(&bytes[..8], b"Q2FALAN\0");
    }

    /// `try_poll` returns `None` on an empty queue, and that is **not** an error.
    #[test]
    fn an_empty_lobby_reports_no_events() {
        let Ok(mut lobby) = Lobby::open_with(
            DeviceId::from_bytes([1; 32]),
            endpoint(1),
            41_001,
            config(70, 21_394, 20),
        ) else {
            return;
        };

        assert!(lobby.view().is_empty());
        assert_eq!(lobby.try_poll(), None);
        assert_eq!(lobby.poll(Duration::from_millis(1)), None);
    }

    /// **An announcement really travels from the socket into the view.**
    ///
    /// The only test in this module covering the whole
    /// "receive → decode → observe → emit event → store in view" chain. It does not
    /// need multicast: the datagram is sent straight to the lobby's ephemeral port
    /// over `127.0.0.1`, where the wildcard-bound socket picks it up, so loopback is
    /// the only requirement.
    #[test]
    fn an_announcement_reaches_the_view() {
        let Ok(mut lobby) = Lobby::open_with(
            DeviceId::from_bytes([1; 32]),
            endpoint(1),
            41_010,
            LanConfig {
                interface: Some(Ipv4Addr::LOCALHOST),
                ..config(71, 0, 60_000)
            },
        ) else {
            return;
        };
        let bound = lobby.sockets[0]
            .local_addr()
            .expect("must have a local address");
        let target = if bound.ip().is_unspecified() {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound.port()))
        } else {
            bound
        };
        let port = target.port();

        let peer = Announcement {
            kind: Kind::Hello,
            sequence: 3,
            device: DeviceId::from_bytes([2; 32]),
            endpoint_key: endpoint(2),
            port: 41_011,
        };
        let injector = UdpSocket::bind((target.ip(), 0)).expect("must bind the injector");
        injector
            .send_to(&peer.encode(), target)
            .expect("must inject the announcement");

        let event = lobby
            .poll(Duration::from_secs(2))
            .expect("must receive one event");
        assert_eq!(event.kind, EventKind::Appeared);
        assert_eq!(event.peer.device, peer.device);
        assert_eq!(event.peer.endpoint_key, peer.endpoint_key);
        assert_eq!(event.peer.port, peer.port);
        assert_eq!(event.peer.status, PeerStatus::Here);
        assert_eq!(
            event.peer.source,
            injector.local_addr().ok(),
            "the address a peer is dialed at is the one its datagram came from"
        );

        assert_eq!(lobby.view().here().len(), 1);
        assert_eq!(lobby.view().get(&peer.device), Some(event.peer));

        injector
            .send_to(
                &peer.encode(),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            )
            .expect("must inject it again");
        assert_eq!(
            lobby.poll(Duration::from_millis(600)),
            None,
            "a resend with an unchanged sequence must not produce an event"
        );
    }

    /// Foreign and broken datagrams are dropped silently and must not dirty the
    /// view.
    ///
    /// The group is shared: other programs on the segment may use it, and anyone can
    /// put arbitrary bytes into it, so dropping quietly is the only correct handling.
    /// Reporting an error would make a completely normal network occurrence look
    /// like a failure.
    #[test]
    fn foreign_and_broken_datagrams_are_ignored() {
        let Ok(mut lobby) = Lobby::open_with(
            DeviceId::from_bytes([3; 32]),
            endpoint(3),
            41_012,
            config(72, 0, 60_000),
        ) else {
            return;
        };
        let bound = lobby.sockets[0]
            .local_addr()
            .expect("must have a local address");
        let target = if bound.ip().is_unspecified() {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound.port()))
        } else {
            bound
        };
        let port = target.port();
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        let injector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("must bind the injector");

        for datagram in [
            b"GET / HTTP/1.1\r\n\r\n".as_slice(),
            b"Q2FALAN\0\x01\x01",
            b"Q2FASYN\0\x02\x01\x00",
        ] {
            injector.send_to(datagram, target).expect("must inject");
        }

        assert_eq!(lobby.poll(Duration::from_millis(500)), None);
        assert!(
            lobby.view().is_empty(),
            "a broken datagram must not enter the view"
        );
    }

    /// **The periodic announce really reaches the group.**
    ///
    /// Listens on `<group, port>` while a `Lobby` announces into the same group every
    /// 20 ms, which pins two things that are easy to get wrong: the announcement goes
    /// to `(group, port)` and not somewhere else, and the periodic announce uses
    /// **this device's** id and endpoint key.
    ///
    /// Returns early when nothing arrives within the timeout: on Windows only the
    /// last binder receives multicast.
    #[test]
    fn the_periodic_announce_reaches_the_group() {
        if !multicast_works() {
            return;
        }
        let config = config(73, 21_395, 20);
        let Ok(listener) = joined_socket(config.group, config.port, Ipv4Addr::LOCALHOST) else {
            return;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("must set the read timeout");

        let me = DeviceId::from_bytes([4; 32]);
        let Ok(lobby) = Lobby::open_with(me, endpoint(4), 41_013, config) else {
            return;
        };

        let mut buffer = [0_u8; 512];
        loop {
            let Ok((length, _)) = listener.recv_from(&mut buffer) else {
                return;
            };
            let Ok(announcement) = Announcement::decode(&buffer[..length]) else {
                continue;
            };
            if announcement.device == me {
                assert_eq!(announcement.kind, Kind::Hello);
                assert_eq!(announcement.endpoint_key, endpoint(4));
                assert_eq!(announcement.port, 41_013);
                break;
            }
        }

        drop(lobby);
    }

    /// After shutdown the worker thread really exits, and shutdown may be called
    /// twice.
    #[test]
    fn shutdown_is_idempotent_and_stops_the_worker() {
        let Ok(mut lobby) = Lobby::open_with(
            DeviceId::from_bytes([5; 32]),
            endpoint(5),
            41_014,
            config(74, 21_396, 10),
        ) else {
            return;
        };

        lobby.shutdown();
        lobby.shutdown();
        assert!(
            lobby.worker.is_none(),
            "the thread handle must have been taken"
        );
    }

    /// A device never turns itself into a peer.
    ///
    /// `IP_MULTICAST_LOOP` loops a device's own multicast back to it and is
    /// deliberately left enabled, so this pins the explicit `device == me` drop in
    /// the worker, the check that keeps self out of the view. The datagram is
    /// injected straight into the lobby's own port, where it is decoded and then
    /// dropped by that check.
    #[test]
    fn a_device_never_becomes_its_own_peer() {
        let me = DeviceId::from_bytes([6; 32]);
        let Ok(mut lobby) = Lobby::open_with(me, endpoint(6), 41_015, config(75, 21_397, 10))
        else {
            return;
        };

        let bound = lobby.sockets[0]
            .local_addr()
            .expect("must have a local address");
        let target = if bound.ip().is_unspecified() {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound.port()))
        } else {
            bound
        };
        let port = target.port();
        let injector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("must bind the injector");
        let mine = Announcement {
            kind: Kind::Hello,
            sequence: 99,
            device: me,
            endpoint_key: endpoint(6),
            port: 41_015,
        };
        injector
            .send_to(
                &mine.encode(),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            )
            .expect("must inject its own announcement");

        assert_eq!(lobby.poll(Duration::from_millis(500)), None);
        assert!(
            lobby.view().get(&me).is_none(),
            "a device must not appear in its own peer list"
        );
    }

    /// One announcement fits the smallest MTU with room for a second one.
    ///
    /// The property is easy to overlook but matters: multicast datagrams must not be
    /// fragmented, since fragmentation loses the "either the whole datagram arrives
    /// or none of it does" semantics, and a fragment would only show the parser half
    /// a datagram. The parser would reject it, but that means the path is unusable on
    /// links with a small MTU.
    ///
    /// The check is on the **budget** rather than "smaller than some number": the
    /// latter could still hold after a field is added, while the budget running out
    /// is the boundary such a change really hits.
    #[test]
    fn the_datagram_leaves_room_within_the_smallest_mtu() {
        /// IPv4 requires every host to reassemble a 576-byte datagram (RFC 791).
        const MIN_IPV4_MTU: usize = 576;
        /// IPv4 header (20) + UDP header (8).
        const HEADERS: usize = 28;
        let payload_budget = MIN_IPV4_MTU - HEADERS;
        assert!(
            DATAGRAM_LEN * 2 <= payload_budget,
            "two {DATAGRAM_LEN}-byte announcements do not fit the {payload_budget}-byte budget"
        );
    }
}
