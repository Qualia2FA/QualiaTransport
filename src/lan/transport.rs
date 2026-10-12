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

//! The LAN data plane: hand a byte string to a peer over an **offline iroh configuration**.
//!
//! # What this module is
//!
//! [`crate::lan::transport::IrohLan`] offers the capability set of `qualia2fa_core::transport::Transport` — send a
//! byte string, receive a byte string, say who the peer is. That trait is defined in the core
//! library, and the **dependency direction is "this crate ← core library"**, so this module
//! cannot refer to it. The type here is a **shape-compatible, independently named** stand-in;
//! the core library (or the FFI layer) joins the two with a forwarding layer that holds no
//! decisions and therefore no untested logic.
//!
//! The public surface:
//!
//! | Method | Does |
//! |--------|------|
//! | [`crate::lan::transport::IrohLan::open`] / [`crate::lan::transport::IrohLan::open_with`] | Build the iroh endpoint and bind a UDP socket |
//! | [`crate::lan::transport::IrohLan::send`] / [`crate::lan::transport::IrohLan::send_blocking`] | Queue one message; `send` returns once the send is accepted, `send_blocking` waits until it is written to the stream |
//! | [`crate::lan::transport::IrohLan::try_receive`] / [`crate::lan::transport::IrohLan::receive_timeout`] | Take one message out of the inbox, or report that there is none |
//! | [`crate::lan::transport::IrohLan::remember_peer`] / [`crate::lan::transport::IrohLan::forget_peer`] / [`crate::lan::transport::IrohLan::connected_peers`] | The peer table and the connections the send path dials from |
//! | [`crate::lan::transport::IrohLan::device_id`] / [`crate::lan::transport::IrohLan::endpoint_key`] / [`crate::lan::transport::IrohLan::bound_sockets`] / [`crate::lan::transport::IrohLan::port`] | This endpoint's own identity and address, for the out-of-band route |
//! | [`crate::lan::transport::IrohLan::shutdown`] | Close every connection and stop the endpoint |
//!
//! # How it behaves
//!
//! - **Connections are dialled on demand.** [`crate::lan::transport::IrohLan::remember_peer`] only records an
//!   address; the first message for that peer opens the QUIC connection, within
//!   [`crate::lan::transport::CONNECT_TIMEOUT`]. An inbound connection is remembered, so the reverse direction
//!   reuses it instead of dialling again.
//! - **Recipient semantics.** [`crate::lan::transport::Recipient::One`] addresses one registered peer and fails
//!   with [`Error::NoConnectionToPeer`] when that peer was never registered;
//!   [`crate::lan::transport::Recipient::All`] goes to every **registered** peer, and "no peer registered" is a
//!   successful send to zero recipients. A peer outside the table never receives anything.
//! - **How it fails.** [`crate::lan::transport::IrohLan::send`] reports only that the request was accepted — the
//!   write happens later on the writer thread, which cannot report back through that return
//!   value, so [`crate::lan::transport::IrohLan::send_blocking`] is the variant that waits. A message longer than
//!   [`crate::lan::transport::MAX_MESSAGE_LEN`] fails with [`Error::PayloadTooLarge`], an unregistered
//!   [`crate::lan::transport::Recipient::One`] with [`Error::NoConnectionToPeer`], and an inbox with nothing in it
//!   with [`Error::TransportEmpty`] — the last one is not a failure, it means "wait, or go
//!   do something else".
//!
//! # Technical details
//!
//! The channel runs on iroh 1.3.0, which supplies QUIC, TLS 1.3 and "prove the peer holds
//! the private key without trusting the network". The offline configuration is four settings,
//! all of them required:
//!
//! ```text
//! presets::Minimal            // crypto provider only: no relay, no DNS, no pkarr
//! relay_mode(Disabled)        // no relay transport is built at all
//! clear_address_lookup()      // no DNS, no pkarr
//! net_report_config(minimal)  // HTTPS probing and captive-portal checks off
//! ```
//!
//! An address reaches a peer out of band, inside a QR code ([`crate::lan::LanAddress`]), or is
//! discovered within one network segment by [`crate::lan::lobby`]; iroh 1.x has no built-in
//! mDNS. The TLS backend is `tls-ring`. The module sits behind the `iroh-lan` feature, which
//! is **off by default**; enabling it raises the MSRV of that build to **1.91**, the version
//! iroh 1.3.0 declares.
//!
//! A message is framed as `kind (1) | device id (32) | payload`, and the device id is the
//! sender's own (see `ENVELOPE_HEADER_LEN` below).
//!
//! # Current state
//!
//! Everything described above is implemented. Out of scope: discovery on the network segment,
//! which lives in [`crate::lan::lobby`] together with the multicast permissions and TTL, and
//! the per-platform permission flows (Android 17's `ACCESS_LOCAL_NETWORK`, the iOS local
//! network usage description), which belong to the platform integration layer.
//!
//! The "no internet" property currently goes exactly as far as the configuration above: no
//! relay transport, no address publishing or lookup, no HTTPS probing or captive-portal
//! check. A whole-lifecycle `netstat` observation showed no socket or connection pointing at
//! a non-local address, but `netstat` cannot see short-lived DNS/HTTPS requests and real
//! packet capture on Windows needs administrator rights. **Packet-capture evidence is
//! therefore still missing**, and until it exists this module must not be described as
//! "proven offline".

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, TransportAddr};
use qualia_dik::DeviceId;
use tokio::runtime::Runtime;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use super::wire::EndpointKey;
use crate::error::{Error, Result};

/// The ALPN of this channel.
///
/// ALPN is part of the QUIC handshake, and a connection whose ALPN does not match is rejected
/// by the peer during that handshake — which also keeps other iroh applications away from
/// this port, with no version negotiation layer of our own. Changing the value is switching
/// to an incompatible protocol version.
pub const ALPN: &[u8] = b"qualia2fa/sync/1";

/// Timeout for establishing a connection.
///
/// On a LAN a connection is either quick (tens of milliseconds across one switch) or never
/// succeeds; 5 seconds is the upper bound a user is still willing to wait.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound for a single message, in bytes.
///
/// The core library keeps a sync payload far below this; the bound here is the transport
/// layer's **independent** one. The length of an incoming message is announced by the peer on
/// the stream, so it must be compared against the bound before anything is allocated;
/// otherwise a few hundred bytes of header could make this process ask for several GiB. The
/// two bounds are defined separately so that relaxing one does not relax the other.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

/// How many received messages the inbox may hold.
///
/// When the caller is too slow to take them, the **newly arrived** message is dropped: a sync
/// payload is idempotent (the core library merges by union), so dropping one only merges a
/// little less this time and the next attempt covers it — while an unbounded inbox would let
/// a peer that keeps sending consume this process's memory.
///
/// The drop is silent and deliberately has no error variant: it happens on a background read
/// task, where no caller is waiting for a result. A caller that wants to observe it should
/// keep its own count (say, "the inbox was full N times in a row").
pub const INBOX_CAPACITY: usize = 64;

/// The message kind marker.
///
/// Only one kind exists today. It is part of the wire format so that a future control message
/// (say, "I am done, stop waiting") needs no change to the stream framing; changing the
/// framing would leave two versions unable to read each other, and an older build may always
/// be present on a LAN.
const MESSAGE_KIND_HELLO: u8 = 0x01;

/// Header of an inbound message: kind marker (1 byte) + device id (32 bytes), that is
/// `kind (1) | device id (32) | payload` for the whole message.
///
/// The transport layer knows the **endpoint public key** (the one proven by the QUIC
/// handshake), while the protocol layer needs the **device id** (the one the user sees and
/// the one on the allow list). The mapping between the two comes from a lobby announcement
/// or a QR code and is **unauthenticated**, so a message carries the sender's own device id
/// and the receiver applies its allow list to it (the core library's `SyncSenderMismatch`
/// exists for that); whether the sender really is the device it claims is settled out of
/// band by the pairing flow. The field does not **establish** trust, it lets the receiver
/// **apply** trust it already has.
const ENVELOPE_HEADER_LEN: usize = 1 + qualia_dik::DEVICE_ID_LEN;

/// One peer's address.
///
/// # One of the two parts is optional, which matters
///
/// `endpoint_key` is **required**: without it no connection can be initiated (an iroh
/// identity is an endpoint public key). `socket` is optional: on the same network segment the
/// IP follows from the source address of the packet, but across segments or behind NAT it may
/// be wrong, and a failure then means "wrong address" rather than "peer absent".
///
/// The QR-code route ([`LanAddress`]) therefore carries **no IP** — two devices of one user
/// may sit on different segments, and a hard-coded IP would only send the peer to a wrong
/// address. An IP appears on the lobby discovery route alone, because that route is answered
/// within one segment.
///
/// [`LanAddress`]: crate::lan::LanAddress
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddress {
    /// The peer's device id (the one the user sees).
    pub device: DeviceId,
    /// The peer's transport-layer endpoint public key.
    pub endpoint_key: EndpointKey,
    /// The peer's IP and port, when known.
    pub socket: Option<SocketAddr>,
}

impl PeerAddress {
    /// Build an address.
    #[must_use]
    pub const fn new(
        device: DeviceId,
        endpoint_key: EndpointKey,
        socket: Option<SocketAddr>,
    ) -> Self {
        Self {
            device,
            endpoint_key,
            socket,
        }
    }

    /// Convert to iroh's address representation.
    ///
    /// # Errors
    ///
    /// [`Error::LanTransport`] when the endpoint public key is not a valid encoding. A 32-byte
    /// input always is, so this path is currently unreachable and stays a `Result` rather than
    /// an `expect`.
    fn to_endpoint_addr(self) -> Result<EndpointAddr> {
        let id = EndpointId::from_bytes(self.endpoint_key.as_bytes()).map_err(|_| {
            Error::LanTransport {
                operation: "endpoint_id",
            }
        })?;
        Ok(match self.socket {
            Some(socket) => EndpointAddr::from_parts(id, [TransportAddr::Ip(socket)]),
            None => EndpointAddr::from_parts(id, []),
        })
    }
}

/// A recipient.
///
/// The same concept as the core library's `Recipient` (whose documentation explains why a
/// recipient must be explicit). It is defined again here because the dependency direction
/// does not allow reusing that one.
///
/// # [`crate::lan::transport::Recipient::All`] means "every known peer", not "every connected peer"
///
/// Connections are dialled on demand, so "the application just opened and nobody has been
/// talked to yet" is exactly the moment a broadcast matters most — with no connection open, a
/// reading of "connected peers" would silently send "here I am, and this is my state" to zero
/// peers while the caller gets `Ok(())`.
///
/// `All` therefore reads the **registered** peers (the table [`crate::lan::transport::IrohLan::remember_peer`]
/// writes), and the send path dials as needed. Anyone outside that table never receives
/// anything — which is both what `Recipient` promises and what the sync protocol's allow list
/// requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    /// Send to this one peer only.
    One(DeviceId),
    /// Send to **every known** peer.
    All,
}

/// One send request, handed to the writer thread to await the connection.
struct SendRequest {
    /// Recipient.
    to: Recipient,
    /// Payload with the envelope header already written.
    framed: Vec<u8>,
    /// Receipt for the outcome.
    done: oneshot::Sender<Result<()>>,
}

/// State shared by the writer thread and the receive path.
struct LanState {
    /// The iroh endpoint.
    endpoint: Endpoint,
    /// This device's id (written into the envelope header).
    device: DeviceId,
    /// Known peer addresses.
    peers: Mutex<HashMap<DeviceId, PeerAddress>>,
    /// Connections already established.
    connections: Mutex<HashMap<DeviceId, iroh::endpoint::Connection>>,
    /// Sending end of the inbox.
    inbox: mpsc::Sender<(DeviceId, Vec<u8>)>,
}

/// The LAN channel (an offline iroh configuration).
///
/// # It runs its own tokio runtime
///
/// iroh is async while this type faces synchronous callers (a UI thread, the core library's
/// synchronous `Transport`), so construction starts a multi-threaded tokio runtime and
/// `block_on` moves the async operations onto it.
///
/// **Async code must not be `block_on`-ed on the runtime it is already running on** (that
/// panics), so callers must not call this type from a tokio worker thread; a desktop UI
/// thread satisfies that. The methods are synchronous for the same reason: two interfaces
/// would make "which one runs on which thread" a question at every call site.
///
/// # Peer addresses are registered explicitly
///
/// A QUIC connection needs the **endpoint public key**, and the mapping "device id → endpoint
/// public key" comes from a lobby announcement or a QR code. This type does not query the
/// lobby itself: the caller registers peers with [`crate::lan::transport::IrohLan::remember_peer`], normally while
/// handling [`crate::lan::lobby::Event`].
pub struct IrohLan {
    /// The async runtime.
    runtime: Runtime,
    /// State shared by the writer thread and the receive path.
    state: Arc<LanState>,
    /// Receiving end of the inbox.
    inbox: AsyncMutex<mpsc::Receiver<(DeviceId, Vec<u8>)>>,
    /// Queue of send requests.
    send_tx: mpsc::UnboundedSender<SendRequest>,
    /// This device's device id.
    device: DeviceId,
    /// This endpoint's endpoint public key.
    endpoint_key: EndpointKey,
}

impl IrohLan {
    /// Open the channel with a fixed endpoint secret key, bound to a system-chosen port.
    ///
    /// # Errors
    ///
    /// [`Error::LanTransport`]: the runtime could not be built, or binding failed (ports
    /// exhausted, system policy blocking UDP).
    pub fn open(device: DeviceId, secret_key: EndpointKey) -> Result<Self> {
        Self::open_with(device, secret_key, None)
    }

    /// Open the channel bound to the given address.
    ///
    /// # Errors
    ///
    /// Same as [`crate::lan::transport::IrohLan::open`].
    pub fn open_with(
        device: DeviceId,
        secret_key: EndpointKey,
        bind: Option<SocketAddr>,
    ) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("qualia-lan-io")
            .build()
            .map_err(|_| Error::LanTransport {
                operation: "runtime",
            })?;

        let endpoint = {
            let mut builder = Endpoint::builder(presets::Minimal)
                .secret_key(iroh::SecretKey::from_bytes(secret_key.as_bytes()))
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
                .net_report_config(iroh::NetReportConfig::minimal())
                .alpns(vec![ALPN.to_vec()]);
            if let Some(addr) = bind {
                builder = builder.bind_addr(addr).map_err(|_| Error::LanTransport {
                    operation: "bind_addr",
                })?;
            }
            runtime
                .block_on(builder.bind())
                .map_err(|_| Error::LanTransport { operation: "bind" })?
        };

        let endpoint_key = EndpointKey::from_bytes(*endpoint.id().as_bytes());
        let (inbox_tx, inbox) = mpsc::channel(INBOX_CAPACITY);
        let (send_tx, send_rx) = mpsc::unbounded_channel();

        let state = Arc::new(LanState {
            endpoint,
            device,
            peers: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            inbox: inbox_tx,
        });

        runtime.spawn(accept_loop(Arc::clone(&state)));
        runtime.spawn(write_loop(Arc::clone(&state), send_rx));

        Ok(Self {
            runtime,
            state,
            inbox: AsyncMutex::new(inbox),
            send_tx,
            device,
            endpoint_key,
        })
    }

    /// This device's device id.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device
    }

    /// This endpoint's endpoint public key (what others dial to reach us).
    #[must_use]
    pub const fn endpoint_key(&self) -> EndpointKey {
        self.endpoint_key
    }

    /// The addresses this endpoint is actually listening on.
    #[must_use]
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.state.endpoint.bound_sockets()
    }

    /// This endpoint's port (taken from the first bound socket).
    ///
    /// Used by the route that puts connection information into a QR code: the code carries the
    /// endpoint public key and the port but no IP — the peer finds the IP in its own routing
    /// table, and a hard-coded IP would break users on another segment.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.bound_sockets().first().map(SocketAddr::port)
    }

    /// Register a peer address.
    ///
    /// Registering the same device again overwrites the entry: a lobby announcement may carry
    /// a changed address (a different network card, a different port), and keeping the old one
    /// would only make the next connection attempt fail once first.
    pub fn remember_peer(&self, peer: PeerAddress) {
        lock(&self.state.peers).insert(peer.device, peer);
    }

    /// Forget a peer, together with its connection.
    pub fn forget_peer(&self, device: &DeviceId) {
        lock(&self.state.peers).remove(device);
        if let Some(connection) = lock(&self.state.connections).remove(device) {
            connection.close(0_u8.into(), b"forgotten");
        }
    }

    /// The peers currently connected, sorted by device id.
    ///
    /// The order is stable, so callers (and tests) need not depend on hash order.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<DeviceId> {
        let mut peers: Vec<DeviceId> = lock(&self.state.connections).keys().copied().collect();
        peers.sort();
        peers
    }

    /// Send one message **without** waiting for it to leave.
    ///
    /// # `Ok` means "the send was accepted"
    ///
    /// Not "the peer received it" — QUIC does not promise that either (a connection can break
    /// at any moment). The real failure (a connection that cannot be established, a stream
    /// that cannot be written) is decided later on the writer thread and therefore **cannot be
    /// reported through this return value**. Use [`crate::lan::transport::IrohLan::send_blocking`] when the outcome
    /// must be known.
    ///
    /// # Errors
    ///
    /// - [`Error::PayloadTooLarge`]: the message exceeds [`crate::lan::transport::MAX_MESSAGE_LEN`].
    /// - [`Error::NoConnectionToPeer`]: [`crate::lan::transport::Recipient::One`] names a peer that was never
    ///   registered. That is a **programming error** on the caller's side (register first,
    ///   then send), and reporting it at once beats dropping the message silently.
    /// - [`Error::LanTransport`]: the writer thread is gone (this value is being dropped).
    pub fn send(&self, to: Recipient, message: &[u8]) -> Result<()> {
        let framed = self.frame(to, message)?;
        self.send_tx
            .send(SendRequest {
                to,
                framed,
                done: oneshot::channel().0,
            })
            .map_err(|_| Error::LanTransport {
                operation: "send_queue",
            })
    }

    /// Send one message and wait until it has been written to the stream.
    ///
    /// Used by tests and by the route where the user pressed sync and the interface shows a
    /// spinner. It **blocks the calling thread** for up to one connection establishment plus
    /// one write.
    ///
    /// # Errors
    ///
    /// The same as [`crate::lan::transport::IrohLan::send`], plus failures of the connection establishment and of the
    /// write itself.
    pub fn send_blocking(&self, to: Recipient, message: &[u8]) -> Result<()> {
        let framed = self.frame(to, message)?;
        let (done_tx, done_rx) = oneshot::channel();
        self.send_tx
            .send(SendRequest {
                to,
                framed,
                done: done_tx,
            })
            .map_err(|_| Error::LanTransport {
                operation: "send_queue",
            })?;
        self.runtime
            .block_on(done_rx)
            .unwrap_or(Err(Error::LanTransport {
                operation: "send_cancelled",
            }))
    }

    /// Validate the recipient, check the length, and write the envelope header.
    ///
    /// The sender id in the header is **this device's own**, never the recipient's.
    fn frame(&self, to: Recipient, message: &[u8]) -> Result<Vec<u8>> {
        if message.len() > MAX_MESSAGE_LEN {
            return Err(Error::PayloadTooLarge {
                needed: message.len(),
                limit: MAX_MESSAGE_LEN,
            });
        }
        if let Recipient::One(device) = to
            && !lock(&self.state.peers).contains_key(&device)
        {
            return Err(Error::NoConnectionToPeer);
        }
        Ok(wrap(self.device, message))
    }

    /// Receive one message, handing back the **device id the sender reported** and the bytes.
    ///
    /// With no message waiting this returns [`Error::TransportEmpty`], which matches the core
    /// library's contract: the caller decides from it whether to wait again, and it is **not**
    /// an error.
    ///
    /// A concurrent receive (another thread holds the inbox) is reported the same way, since
    /// blocking is not what "try" promises.
    ///
    /// # Errors
    ///
    /// [`Error::TransportEmpty`] when the inbox holds no message.
    pub fn try_receive(&self) -> Result<(DeviceId, Vec<u8>)> {
        match self.inbox.try_lock() {
            Ok(mut inbox) => match inbox.try_recv() {
                Ok(message) => Ok(message),
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    Err(Error::TransportEmpty)
                }
            },
            Err(_) => Err(Error::TransportEmpty),
        }
    }

    /// Receive one message, blocking for at most `timeout`.
    ///
    /// A timeout returns [`Error::TransportEmpty`], the same result as "no message waiting":
    /// the caller either waits again or goes off to do something else.
    ///
    /// # Errors
    ///
    /// [`Error::TransportEmpty`] on timeout or when the queue is disconnected.
    pub fn receive_timeout(&self, timeout: Duration) -> Result<(DeviceId, Vec<u8>)> {
        let received = self.runtime.block_on(async {
            let mut inbox = self.inbox.lock().await;
            tokio::time::timeout(timeout, inbox.recv()).await
        });
        match received {
            Ok(Some(message)) => Ok(message),
            Ok(None) | Err(_) => Err(Error::TransportEmpty),
        }
    }

    /// Close the channel: end every connection and stop the iroh endpoint.
    ///
    /// Calling it more than once is safe.
    pub fn shutdown(&self) {
        self.runtime.block_on(self.state.endpoint.close());
    }
}

impl Drop for IrohLan {
    fn drop(&mut self) {
        if !self.state.endpoint.is_closed() {
            self.shutdown();
        }
    }
}

/// Take the lock, ignoring poisoning.
///
/// Poisoning means **another thread panicked while holding the lock**, and the data structure
/// here (a hash map) cannot be left in a dangerous partially updated state by that: the insert
/// either happened or it did not. Letting later calls continue beats making the whole channel
/// unusable because of an unrelated panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Add the envelope header to a message.
fn wrap(device: DeviceId, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_HEADER_LEN + message.len());
    out.push(MESSAGE_KIND_HELLO);
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(message);
    out
}

/// Strip the envelope header, handing back the sender's self-reported device id and the
/// payload.
///
/// # Errors
///
/// [`Error::LanTransport`] when the input is too short or the kind marker is unknown. Both
/// mean a peer's programming error or an attack, and dropping the message is all that can be
/// done with it: parsing a marker we do not know would turn "a new message kind is added
/// later" into a silent misunderstanding.
fn unwrap_message(bytes: &[u8]) -> Result<(DeviceId, Vec<u8>)> {
    if bytes.len() < ENVELOPE_HEADER_LEN {
        return Err(Error::LanTransport {
            operation: "short_message",
        });
    }
    if bytes[0] != MESSAGE_KIND_HELLO {
        return Err(Error::LanTransport {
            operation: "unknown_message_kind",
        });
    }
    let mut device = [0_u8; qualia_dik::DEVICE_ID_LEN];
    device.copy_from_slice(&bytes[1..ENVELOPE_HEADER_LEN]);
    Ok((
        DeviceId::from_bytes(device),
        bytes[ENVELOPE_HEADER_LEN..].to_vec(),
    ))
}

/// Accept inbound connections and start one read loop per connection.
///
/// The pending accept and the handshake are two separate awaits. A handshake that fails (an
/// ALPN mismatch, a peer that cannot produce its private key) is normal on a shared network
/// and is dropped without a log entry.
async fn accept_loop(state: Arc<LanState>) {
    while let Some(incoming) = state.endpoint.accept().await {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            read_connection(state, connection).await;
        });
    }
}

/// Read every inbound stream on a connection until the connection ends.
///
/// The device id a message reports is also recorded as the owner of the connection, because
/// the endpoint public key alone cannot be mapped back to a device id; that record is what
/// lets a later targeted send reuse the connection. A message that does not fit the inbox is
/// dropped without an acknowledgement and without a retry.
async fn read_connection(state: Arc<LanState>, connection: iroh::endpoint::Connection) {
    while let Ok((_send, mut recv)) = connection.accept_bi().await {
        let Ok(bytes) = recv.read_to_end(MAX_MESSAGE_LEN).await else {
            continue;
        };
        let Ok((sender, message)) = unwrap_message(&bytes) else {
            continue;
        };
        if sender != state.device {
            lock(&state.connections).insert(sender, connection.clone());
        }
        if state.inbox.try_send((sender, message)).is_err() {
            continue;
        }
    }
}

/// Process the queue of send requests.
///
/// A request's receipt may already have no waiter, because `send` does not wait for one.
async fn write_loop(state: Arc<LanState>, mut requests: mpsc::UnboundedReceiver<SendRequest>) {
    while let Some(request) = requests.recv().await {
        let result = deliver(&state, request.to, &request.framed).await;
        let _ = request.done.send(result);
    }
}

/// Deliver one message for real.
///
/// [`crate::lan::transport::Recipient::All`] expands to the **registered** peers rather than the connected ones, and
/// an expansion to zero recipients is a normal state, not a failure.
async fn deliver(state: &Arc<LanState>, to: Recipient, framed: &[u8]) -> Result<()> {
    let targets: Vec<DeviceId> = match to {
        Recipient::One(device) => vec![device],
        Recipient::All => {
            let mut all: Vec<DeviceId> = lock(&state.peers).keys().copied().collect();
            all.sort();
            all
        }
    };

    let mut failure = None;
    for device in targets {
        if let Err(error) = deliver_to_one(state, device, framed).await {
            failure = Some(error);
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Deliver one message to one peer, establishing the connection first if needed.
///
/// `finish` closes the send direction; no acknowledgement is awaited, because the core
/// library's sync is **two independent messages** (I give you my state, you give me yours) and
/// waiting for an ack here would only turn one sync into two round trips.
async fn deliver_to_one(state: &Arc<LanState>, device: DeviceId, framed: &[u8]) -> Result<()> {
    let connection = ensure_connection(state, device).await?;
    let (mut send, _recv) = connection
        .open_bi()
        .await
        .map_err(|_| Error::LanTransport {
            operation: "open_bi",
        })?;
    send.write_all(framed)
        .await
        .map_err(|_| Error::LanTransport { operation: "write" })?;
    send.finish().map_err(|_| Error::LanTransport {
        operation: "finish",
    })?;
    Ok(())
}

/// Get the connection to a peer, establishing it if needed.
async fn ensure_connection(
    state: &Arc<LanState>,
    device: DeviceId,
) -> Result<iroh::endpoint::Connection> {
    if let Some(connection) = lock(&state.connections).get(&device) {
        return Ok(connection.clone());
    }

    let Some(address) = lock(&state.peers).get(&device).copied() else {
        return Err(Error::NoConnectionToPeer);
    };
    let target = address.to_endpoint_addr()?;

    let connecting = tokio::time::timeout(CONNECT_TIMEOUT, state.endpoint.connect(target, ALPN))
        .await
        .map_err(|_| Error::LanTransport {
            operation: "connect_timeout",
        })?
        .map_err(|_| Error::LanTransport {
            operation: "connect",
        })?;
    lock(&state.connections).insert(device, connecting.clone());
    Ok(connecting)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn device(seed: u8) -> DeviceId {
        DeviceId::from_bytes([seed; 32])
    }

    fn key(seed: u8) -> EndpointKey {
        EndpointKey::from_bytes([seed.wrapping_mul(7).wrapping_add(1); 32])
    }

    /// Open a pair of channels on the loopback, each registering **which port** the other one
    /// listens on.
    ///
    /// Both endpoints bind a system-chosen port, and `socket` in a [`PeerAddress`] is
    /// optional: without it iroh has an endpoint public key and no address at all, so nothing
    /// can be dialled. This is the shape of the QR-code route in a real deployment (the code
    /// carries the public key and the port, the peer finds the IP), with the IP filled in as
    /// the local loopback.
    ///
    /// Returns `None` when either endpoint cannot be opened, so a machine with no usable
    /// loopback skips the tests built on it.
    fn pair(seed_a: u8, seed_b: u8) -> Option<(IrohLan, IrohLan)> {
        let a = IrohLan::open(device(seed_a), key(seed_a)).ok()?;
        let b = IrohLan::open(device(seed_b), key(seed_b)).ok()?;

        let a_port = a.port()?;
        let b_port = b.port()?;
        a.remember_peer(PeerAddress::new(
            device(seed_b),
            b.endpoint_key(),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, b_port))),
        ));
        b.remember_peer(PeerAddress::new(
            device(seed_a),
            a.endpoint_key(),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, a_port))),
        ));
        Some((a, b))
    }

    /// The endpoint public key **comes from the given endpoint secret key**, and is
    /// deterministic: one secret key yields one public key, different secret keys yield
    /// different public keys.
    ///
    /// The public key is not equal to the secret key bytes: `SecretKey::from_bytes` takes an
    /// **Ed25519 seed** and derives the public key from it. The property that matters is
    /// determinism (so "the device identity is bound to the endpoint identity" is
    /// reproducible) together with distinctness (so the endpoint identity really separates
    /// devices, and "carry the endpoint public key out of band in a QR code" keeps working).
    ///
    /// Binds real endpoints; sends nothing.
    #[test]
    fn the_endpoint_key_is_deterministic_and_derived_from_the_secret() {
        let Ok(first) = IrohLan::open(device(1), key(1)) else {
            return;
        };
        let Ok(second) = IrohLan::open(device(2), key(1)) else {
            return;
        };
        let Ok(other) = IrohLan::open(device(1), key(2)) else {
            return;
        };

        assert_eq!(
            first.endpoint_key(),
            second.endpoint_key(),
            "the same secret key must derive the same endpoint key"
        );
        assert_ne!(
            first.endpoint_key(),
            other.endpoint_key(),
            "different secret keys must derive different endpoint keys"
        );
    }

    /// The bound port is really a usable port, and `port()` agrees with `bound_sockets()`.
    ///
    /// Binds a real endpoint; sends nothing.
    #[test]
    fn the_bound_port_is_reported_consistently() {
        let Ok(lan) = IrohLan::open(device(3), key(3)) else {
            return;
        };
        let sockets = lan.bound_sockets();
        assert!(!sockets.is_empty(), "at least one socket must be bound");
        assert_eq!(lan.port(), Some(sockets[0].port()));
        assert_ne!(
            lan.port(),
            Some(0),
            "port 0 means 'let the system pick', not the value it picked"
        );
    }

    /// **Two endpoints on one machine really do exchange a message**: a full QUIC path (TLS
    /// handshake, stream, message framing) over the loopback, with no second machine involved.
    ///
    /// Skipped when the endpoints cannot be opened or nothing arrives — on a machine without a
    /// usable loopback the test proves nothing, and failing there would only add noise.
    ///
    /// Needs real loopback traffic.
    #[test]
    fn two_endpoints_exchange_a_message() {
        let Some((a, b)) = pair(2, 3) else {
            return;
        };

        let payload = b"\x00\x01\x02 sync payload \xff\xfe";
        if a.send_blocking(Recipient::One(device(3)), payload).is_err() {
            return;
        }

        let Ok((sender, received)) = b.receive_timeout(Duration::from_secs(5)) else {
            return;
        };
        assert_eq!(sender, device(2), "the sender id must come from this device");
        assert_eq!(received, payload, "the bytes must arrive unchanged");
    }

    /// The reverse direction works as well: a QUIC connection is bidirectional, and on a
    /// network discovered by multicast either side may initiate.
    ///
    /// Needs real loopback traffic.
    #[test]
    fn the_other_direction_works_too() {
        let Some((a, b)) = pair(4, 5) else {
            return;
        };

        if b.send_blocking(Recipient::One(device(4)), b"from b")
            .is_err()
        {
            return;
        }
        let Ok((sender, received)) = a.receive_timeout(Duration::from_secs(5)) else {
            return;
        };
        assert_eq!(sender, device(5));
        assert_eq!(received, b"from b");
    }

    /// Once a connection exists, the reverse direction reuses it: a receiver remembers which
    /// peer an inbound connection belongs to, so answering does not need the peer's address.
    ///
    /// Needs real loopback traffic.
    #[test]
    fn an_inbound_connection_is_remembered_for_the_reverse_direction() {
        let Some((a, b)) = pair(6, 7) else {
            return;
        };

        if a.send_blocking(Recipient::One(device(7)), b"hi").is_err() {
            return;
        }
        let Ok(_) = b.receive_timeout(Duration::from_secs(5)) else {
            return;
        };
        assert!(
            b.connected_peers().contains(&device(6)),
            "the owner of this connection must be remembered after a message arrives, got {:?}",
            b.connected_peers()
        );
    }

    /// Sending to an unregistered peer is an error **at once**, not a silent drop.
    ///
    /// Binds a real endpoint; sends nothing.
    #[test]
    fn sending_to_an_unregistered_peer_is_an_error() {
        let Ok(lan) = IrohLan::open(device(8), key(8)) else {
            return;
        };
        let result = lan.send(Recipient::One(device(99)), b"x");
        assert!(
            matches!(result, Err(Error::NoConnectionToPeer)),
            "should report no connection to that peer, got {result:?}"
        );
    }

    /// A message over the bound is rejected **before** anything is allocated.
    ///
    /// Binds a real endpoint; sends nothing.
    #[test]
    fn an_oversized_message_is_rejected_before_allocating() {
        let Ok(lan) = IrohLan::open(device(9), key(9)) else {
            return;
        };
        lan.remember_peer(PeerAddress::new(device(10), key(10), None));
        let too_long = vec![0_u8; MAX_MESSAGE_LEN + 1];
        let result = lan.send(Recipient::One(device(10)), &too_long);
        match result {
            Err(Error::PayloadTooLarge { needed, limit }) => {
                assert_eq!(limit, MAX_MESSAGE_LEN);
                assert_eq!(needed, MAX_MESSAGE_LEN + 1);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    /// **A `Recipient::All` send reaches nobody outside the table.** The contract is that it
    /// must not degrade into a broadcast to peers that were never registered: with three
    /// endpoints, the one that never registered anybody receives nothing.
    ///
    /// Needs real loopback traffic.
    #[test]
    fn a_broadcast_only_reaches_connected_peers() {
        let Some((a, b)) = pair(11, 12) else {
            return;
        };
        let Ok(c) = IrohLan::open(device(13), key(13)) else {
            return;
        };

        if a.send_blocking(Recipient::All, b"to all").is_err() {
            return;
        }
        assert!(
            b.receive_timeout(Duration::from_secs(5)).is_ok(),
            "a connected peer must receive the broadcast"
        );
        assert!(
            c.receive_timeout(Duration::from_secs(1)).is_err(),
            "a peer that was never connected must receive nothing"
        );
    }

    /// "Nothing waiting" is [`Error::TransportEmpty`] and no other error, both for an
    /// immediate receive and for a timeout; the core library relies on that to tell "keep
    /// waiting" from "reject".
    ///
    /// Binds a real endpoint; sends nothing.
    #[test]
    fn an_empty_inbox_reports_no_session_found() {
        let Ok(lan) = IrohLan::open(device(14), key(14)) else {
            return;
        };
        let result = lan.try_receive();
        assert!(
            matches!(result, Err(Error::TransportEmpty)),
            "an empty inbox should report no message, got {result:?}"
        );
        let result = lan.receive_timeout(Duration::from_millis(50));
        assert!(
            matches!(result, Err(Error::TransportEmpty)),
            "a timeout should report no message, got {result:?}"
        );
    }

    /// The envelope header is pinned byte for byte, and the sender id is the local device's.
    ///
    /// Pure logic, no sockets.
    #[test]
    fn the_envelope_header_is_pinned() {
        let me = DeviceId::from_bytes([0xAB; 32]);
        let framed = wrap(me, b"body");
        assert_eq!(framed.len(), ENVELOPE_HEADER_LEN + 4);
        assert_eq!(framed[0], MESSAGE_KIND_HELLO);
        assert_eq!(&framed[1..33], &[0xAB; 32]);
        assert_eq!(&framed[33..], b"body");

        let (sender, message) = unwrap_message(&framed).expect("a self-framed message must decode");
        assert_eq!(sender, me);
        assert_eq!(message, b"body");
    }

    /// An empty payload body is legal (a "request" carries none); a header that is too short
    /// or carries an unknown kind marker is not.
    ///
    /// Pure logic, no sockets.
    #[test]
    fn malformed_envelopes_are_rejected() {
        assert!(unwrap_message(&[]).is_err(), "empty input must be rejected");
        assert!(
            unwrap_message(&[MESSAGE_KIND_HELLO]).is_err(),
            "the kind byte only"
        );
        assert!(unwrap_message(&[0x7F; 33]).is_err(), "unknown kind");

        let me = DeviceId::from_bytes([1; 32]);
        let (sender, message) = unwrap_message(&wrap(me, b"")).expect("an empty message body is legal");
        assert_eq!(sender, me);
        assert!(message.is_empty());
    }

    /// Shutting down twice is safe.
    ///
    /// Binds a real endpoint; sends nothing.
    #[test]
    fn shutdown_is_idempotent() {
        let Ok(lan) = IrohLan::open(device(15), key(15)) else {
            return;
        };
        lan.shutdown();
        lan.shutdown();
        assert!(lan.state.endpoint.is_closed());
    }

    /// After a peer is forgotten, a targeted send is "no connection to that peer" again.
    ///
    /// Needs real loopback traffic.
    #[test]
    fn forgetting_a_peer_removes_its_connection() {
        let Some((a, _b)) = pair(16, 17) else {
            return;
        };
        if a.send_blocking(Recipient::One(device(17)), b"x").is_err() {
            return;
        }
        a.forget_peer(&device(17));
        let result = a.send(Recipient::One(device(17)), b"y");
        assert!(
            matches!(result, Err(Error::NoConnectionToPeer)),
            "after forgetting, it should report no connection to that peer, got {result:?}"
        );
    }
}
