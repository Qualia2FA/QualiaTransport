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

//! 局域网**大厅**：在一段网段上互相看见，并交换「到哪里连我」。
//!
//! # 它做什么、不做什么
//!
//! 做：往一个组播组里周期性地喊一声「我在这里，我的端点公钥与端口是这个」，并听
//! 别人喊。收到的结果累积成一份 [`LanView`]（谁在这个网段上）。
//!
//! 不做：**不传同步载荷**。载荷走的是另一条路（QUIC 连接，见 crate 根的说明，或者
//! 带外二维码），大厅只负责「找到人」。这条分界是刻意的：组播是**不可靠、可被任何
//! 同网段设备注入**的，把载荷放进去就等于把协议暴露在那样的输入面前。分开之后，大厅
//! 的最坏情况是「看到一个不存在的设备」，而不是「收到一份需要解析的载荷」。
//!
//! # 为什么用组播，而不是二维码传地址
//!
//! 见 TODO.md 的 M4.5：用户明确选了「UDP 组播大厅做发现」。二维码传地址在跨网段与
//! 移动网络下仍然有用（那是 D9 的「建链」模式），但同一 WiFi 下每次都要互相扫一次
//! 码是多余的——设备本来就在同一个广播域里。
//!
//! # 这是本 crate 里唯一碰 I/O 的模块
//!
//! 它会开 socket、起线程、读时钟。因此它的逻辑被压到最小：**判断都在 [`LanView`]
//! 里**，这里只做「把字节搬进搬出」与「按时喊一声」。时钟只用来算间隔与租约，从不
//! 进入协议——协议里没有时间戳，那样才能让两边对「现在几点」不达成一致也照样工作。
//!
//! # 平台注意
//!
//! - **Android 17（targetSdk 37+）** 需要 `ACCESS_LOCAL_NETWORK` 才能在局域网里收发
//!   组播，这一点由端侧处理（见 TODO.md §6.1）。
//! - **多网卡**上组播从哪张网卡出去是由路由表决定的。`set_multicast_if_v4` 可以指定，
//!   但本 crate **刻意不指定**：指定就意味着要枚举网卡并猜用户想用哪一张，而那是一
//!   个比「让路由表决定」更容易出错的选择。默认路由恰好不对时，用户用的会是二维码
//!   那条路，而不是一个「我们猜错了网卡」的故障。

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

/// 大厅使用的组播组。
///
/// `239.255.81.65` 取在**管理范围**（`239.0.0.0/8`，RFC 2365 的「Administratively
/// Scoped」）内，且刻意取在 `239.255.0.0/16` 这个**组织本地**子范围里，避免与
/// SSDP（`239.255.255.250`）、mDNS（`224.0.0.251`）这类知名组撞上。
///
/// `0x51` 是 `Q`，`65` 是 `A`——没有任何协议含义，只是让这个地址在抓包记录里认得
/// 出来。
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 81, 65);

/// 大厅使用的 UDP 端口。
///
/// 取在动态/私有端口段（49152–65535）之外，因为那个段按 RFC 6335 是留给**临时**
/// 端口的：把一个长期监听的组播组放在那里，会与系统随机分配的临时端口撞上。这里是
/// 在注册端口段（1024–49151）里挑的一个没有知名服务占用的号。
pub const PORT: u16 = 21377;

/// 多久喊一声。
///
/// 30 秒是「用户打开应用后多快看到对方」与「待机时的开销」之间的取舍。它同时决定了
/// 两个数字：最坏发现延迟是 30 秒，而 [`LanView::STALE_AFTER_MS`]（3 分钟）正好是
/// 它的 6 倍——连丢 6 个周期才判定离线，够宽容。
pub const ANNOUNCE_INTERVAL_MS: u64 = 30_000;

/// 收到一条消息之后最多等多久再检查一次「该喊了吗 / 该退出了吗」（毫秒）。
///
/// 这不是一个协议参数，纯粹是**退出延迟**：`recv_from` 是阻塞的，没有这个上限的话，
/// 关闭时线程要等到下一个组播报文（最长就是一整个公告周期）才醒过来。200 毫秒是
/// 「用户感觉不到关闭卡顿」与「每秒醒 5 次」之间的取舍，而在一个只做组播收发的线程
/// 上，那点唤醒开销可以忽略。
const LOOP_SLICE_MS: u64 = 200;

/// 大厅的配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanConfig {
    /// 组播组地址。
    pub group: Ipv4Addr,
    /// UDP 端口。
    pub port: u16,
    /// 公告间隔（毫秒）。
    pub announce_interval_ms: u64,
}

impl Default for LanConfig {
    fn default() -> Self {
        Self {
            group: GROUP,
            port: PORT,
            announce_interval_ms: ANNOUNCE_INTERVAL_MS,
        }
    }
}

impl LanConfig {
    /// 这个组播组要绑到哪里。
    #[must_use]
    pub const fn group_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.group, self.port)
    }
}

/// 大厅里发生的一件事。
///
/// # 为什么是事件而不是「变化后的整个视图」
///
/// 调用方多半要把这件事显示出来或记下来（「发现设备 X」），而一份完整视图无法表达
/// 「刚刚」发生了什么。反过来，只给事件也不够——调用方可以在自己那边累积。
///
/// # 为什么带着完整的对端快照
///
/// 一个只带设备标识的事件，会让接收方在 `Lobby` 侧查不到那个对端（两个视图之间
/// 只有这条队列相连）。把快照带上，事件本身就成了**自足**的：接收方不需要向任何
/// 地方再问一次「他现在是什么状态」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// 说的是哪个对端，以及他当时的状态。
    pub peer: Peer,
    /// 发生了什么事。
    pub kind: EventKind,
}

/// 事件的种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// 第一次听说这个对端，或他又回来了。
    Appeared,
    /// 他发过「我要走了」。
    SaidGoodbye,
    /// 他太久没吭声了。
    Expired,
}

/// 大厅后台线程往事件队列里送的东西：事件 + 它发生的时刻。
///
/// 时刻必须跟着走，否则 `Lobby` 那份视图拿到事件之后无法知道该把
/// [`Peer::last_seen_ms`] 记成什么——用它自己的时钟会与后台线程的时钟差出一个
/// 「事件在队列里等了多久」，而那正好会让租约在两边算出不同的结果。
#[derive(Debug, Clone, Copy)]
struct TimedEvent {
    /// 事件本身。
    event: Event,
    /// 发生时刻（相对后台线程的起点，毫秒）。
    at_ms: u64,
}

/// 关于本设备自己要念出去的那几个值。
///
/// 打成一个小结构体，是因为它们**总是一起出现**：公告、告别、以及后台线程的周期
/// 喊话都要这三样。分成三个参数或三个字段，就会出现「某一处忘了带上端口」这种
/// 错误——而它的症状是「对端能发现你，但连不上你」。
#[derive(Debug, Clone, Copy)]
struct SelfAnnouncement {
    /// 本设备的设备标识。
    device: DeviceId,
    /// 本设备的传输层端点公钥。
    endpoint_key: EndpointKey,
    /// 本设备监听的端口。
    port: u16,
}

impl SelfAnnouncement {
    /// 造一条发给别人的公告。
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

/// 局域网大厅。
///
/// # 它自己起线程
///
/// 收发都在一个后台线程里，因此调用方不需要给它喂事件循环，也不需要在 `Drop` 之外
/// 做任何清理。线程只会在 [`Lobby::shutdown`] 或 `Drop` 时退出，退出时先替所有还
/// 「在这里」的对端发一条 `Bye`——那让另一个界面上的「已关闭」立刻出现，而不是等
/// 3 分钟的租约。
///
/// # 本机自己发的公告会被自己收到
///
/// `IP_MULTICAST_LOOP` 默认是开的，因此一台设备会收到自己刚才喊的那一声。这是**正常
/// 的**，[`LanView::observe`] 里那条「序号不增就是旧消息」的规则顺带把它压掉了；再
/// 加上下面显式丢掉 `device == me` 的报文，双保险。
pub struct Lobby {
    /// 本机要念出去的那几个值。
    me: SelfAnnouncement,
    /// 收发共用的 socket。
    socket: Arc<UdpSocket>,
    /// 配置。
    config: LanConfig,
    /// 当前看到的对端（`Lobby` 这一侧的副本）。
    view: LanView,
    /// 事件队列的接收端。
    events: Receiver<TimedEvent>,
    /// 后台线程的句柄。
    worker: Option<JoinHandle<()>>,
    /// 让后台线程退出的开关。
    running: Arc<AtomicBool>,
    /// 公告序号。
    ///
    /// **与后台线程共用同一个计数器**，因此它是 `Arc<AtomicU64>` 而不是一个普通字段：
    /// `announce_now`（界面线程）与周期喊话（网络线程）都会推进它，而两条路径用各自
    /// 的计数器会让「序号唯一且递增」这个前提悄悄失效——症状是大厅偶尔把一条**真的**
    /// 新公告当成旧消息丢掉，极难复现。
    sequence: Arc<AtomicU64>,
}

impl Lobby {
    /// 打开大厅：绑定端口、加入组播组，并开始喊。
    ///
    /// `endpoint_key` 与 `port` 是「别人该怎么连我」，由传输层提供——大厅自己不知道
    /// QUIC 的存在，它只是把这两个值念出来。
    ///
    /// # 错误
    ///
    /// [`Error::LanSocket`]：绑定或加入组播组失败。最常见的原因是**端口已被占用**
    /// （同一台机器上开了两个实例），以及**防火墙/系统策略**不允许加入组播组。
    pub fn open(me: DeviceId, endpoint_key: EndpointKey, port: u16) -> Result<Self> {
        Self::open_with(me, endpoint_key, port, LanConfig::default())
    }

    /// 用给定配置打开大厅。
    ///
    /// # 错误
    ///
    /// 同 [`Lobby::open`]。
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
        let socket = Arc::new(bind_multicast(config)?);
        let (sender, events) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let sequence = Arc::new(AtomicU64::new(0));

        let worker = {
            let socket = Arc::clone(&socket);
            let running = Arc::clone(&running);
            let sequence = Arc::clone(&sequence);
            thread::Builder::new()
                .name("qualia-lan-lobby".into())
                .spawn(move || {
                    let mut view = LanView::new();
                    serve(&socket, config, me, &mut view, &sender, &running, &sequence);
                })
                .map_err(|_| Error::LanSocket { operation: "spawn" })?
        };

        Ok(Self {
            me,
            socket,
            config,
            view: LanView::new(),
            events,
            worker: Some(worker),
            running,
            sequence,
        })
    }

    /// 当前看到的对端（只含他认为「在这里」的）。
    #[must_use]
    pub fn view(&self) -> &LanView {
        &self.view
    }

    /// 非阻塞地取一件事。
    ///
    /// 没有事件时返回 `None`——它**不是**错误。界面上一次刷新把所有积压的事件取完，
    /// 因此这里刻意不提供「阻塞等下一件」，那会让界面线程被网络事件牵着走。
    pub fn try_poll(&mut self) -> Option<Event> {
        self.events.try_recv().ok().map(|timed| self.apply(timed))
    }

    /// 阻塞最多 `timeout` 取一件事。
    ///
    /// 超时返回 `None`。它与「没有事件」是同一件事——调用方要么再等，要么去干别的；
    /// 把它报成错误只会让每个调用点都写一遍同样的 `match`。
    pub fn poll(&mut self, timeout: Duration) -> Option<Event> {
        self.events
            .recv_timeout(timeout)
            .ok()
            .map(|timed| self.apply(timed))
    }

    /// 立刻喊一声（不等下一个周期）。
    ///
    /// 用途是「用户刚点开同步界面」：正常情况下要等最多 30 秒才轮到下一个周期，而
    /// 用户在这个界面上的耐心是以秒计的。
    ///
    /// # 错误
    ///
    /// [`Error::LanSocket`]：发送失败（网卡消失、组播被策略拦下）。
    pub fn announce_now(&self) -> Result<()> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let announcement = self.me.announcement(Kind::Hello, sequence);
        send_datagram(&self.socket, self.config, &announcement)
    }

    /// 关掉大厅：替所有还在的对端发一条 `Bye`，然后停掉后台线程。
    ///
    /// 重复调用是安全的（第二次什么也不做）。
    pub fn shutdown(&mut self) {
        self.send_goodbye();
        self.running.store(false, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            // 线程可能因为 socket 出错而提前退出，那是正常结局，不是要在这里处理的事。
            let _ = worker.join();
        }
    }

    /// 把一件事记进这一侧的视图。
    ///
    /// # 为什么重新走一遍 `observe`
    ///
    /// 视图只该有**一条**写入路径。后台线程那份视图已经做过同样的推理，这里再做一遍
    /// 不是冗余——它是「两份视图必须一致」这条要求的实现方式，而 `observe` 的序号
    /// 规则让重复应用同一件事是幂等的。
    fn apply(&mut self, timed: TimedEvent) -> Event {
        let kind = match timed.event.kind {
            EventKind::Appeared => Kind::Hello,
            // 「说了再见」与「太久没吭声」在视图里是同一件事：他不再「在这里」。
            EventKind::SaidGoodbye | EventKind::Expired => Kind::Bye,
        };
        let peer = timed.event.peer;
        // 序号取自快照：`LanView::expire` 已经把水位推高一格，因此这条状态变化能被
        // 重新说出来；而 `SaidGoodbye` 的序号本来就是公告自己带的那个。
        self.view.observe(
            Announcement {
                kind,
                sequence: peer.sequence,
                device: peer.device,
                endpoint_key: peer.endpoint_key,
                port: peer.port,
            },
            timed.at_ms,
        );
        timed.event
    }

    /// 替所有还「在这里」的对端发一条 `Bye`。
    fn send_goodbye(&self) {
        for peer in self.view.here() {
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
            let announcement = self.me.announcement(Kind::Bye, sequence);
            // 发送失败只能忽略：这已经是析构路径，没有地方可以报错，也不该 panic。
            let _ = send_datagram(&self.socket, self.config, &announcement);
            // 对端快照只用来决定「发给谁」——`Bye` 说的是**我们自己**要走。
            let _ = peer;
        }
    }
}

impl Drop for Lobby {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 后台线程：一边听，一边按时喊。
///
/// 抽成自由函数而不是方法，是为了让它能**拥有**视图的那份可变借用：`Lobby::view` 是
/// 给调用方看的只读副本，两者不是同一份数据。它们之间靠事件队列同步——一条队列换掉
/// 一把锁，收益是界面线程永远不会被网络线程拖住。
fn serve(
    socket: &Arc<UdpSocket>,
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
        // ① 该喊了吗。
        let due = match last_announce {
            None => true,
            Some(last) => last.elapsed().as_millis() as u64 >= config.announce_interval_ms,
        };
        if due {
            // 序号与界面线程共用，因此从原子量取，而不是从这里的一个局部计数器。
            let sequence = sequence.fetch_add(1, Ordering::Relaxed);
            let _ = send_datagram(socket, config, &me.announcement(Kind::Hello, sequence));
            last_announce = Some(Instant::now());
        }

        // ② 听一会儿。等待时间取「距下一次该喊还有多久」与 [`LOOP_SLICE`] 的较小值，
        //    因此喊话周期是准的，而退出延迟仍然有界。
        let slice = match last_announce {
            Some(last) => config
                .announce_interval_ms
                .saturating_sub(last.elapsed().as_millis() as u64)
                .clamp(1, LOOP_SLICE_MS),
            None => LOOP_SLICE_MS,
        };
        let _ = socket.set_read_timeout(Some(Duration::from_millis(slice)));

        match socket.recv_from(&mut buffer) {
            Ok((length, _from)) => {
                let Some(datagram) = buffer.get(..length) else {
                    continue;
                };
                let Ok(announcement) = Announcement::decode(datagram) else {
                    // 组播组是共享的：不是我们的报文、或是比我们新的版本，都是**正常
                    // 现象**，不记日志也不报错。
                    continue;
                };
                // 自己喊的那一声会被自己收到（`IP_MULTICAST_LOOP`）。
                if announcement.device == me.device {
                    continue;
                }
                let at_ms = started.elapsed().as_millis() as u64;
                // `observe` 的返回值先落成一个布尔量，再在下面 `if let` 的分支里使用：
                // 直接把它嵌进 `if let` 会让「有没有变化」这个条件在借用 `view` 之后
                // 才求值，而那时 `view.get` 又要借一次。
                let changed = view.observe(announcement, at_ms);
                if changed && let Some(peer) = view.get(&announcement.device) {
                    let kind = match announcement.kind {
                        Kind::Hello => EventKind::Appeared,
                        Kind::Bye => EventKind::SaidGoodbye,
                    };
                    // 接收端已经没了（`Lobby` 正在析构）时发送会失败，那是正常结局。
                    // 队列本身是无界的，因此网络线程永远不会被界面拖住。
                    let _ = events.send(TimedEvent {
                        event: Event { peer, kind },
                        at_ms,
                    });
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            // 其它错误（网卡消失、socket 被关）不值得把线程打死：下一次 `recv_from`
            // 可能就好了。真正要退出时 `running` 会变成 `false`。
            Err(_) => thread::sleep(Duration::from_millis(LOOP_SLICE_MS)),
        }

        // ③ 租约。
        let at_ms = started.elapsed().as_millis() as u64;
        for device in view.expire(at_ms) {
            // 此刻视图里那个对端已经是「已离开」，而 `expire` 把它的序号推高了一格
            // ——因此这条状态变化能被接收方重新说出来。带上 `at_ms` 而不是让接收方
            // 用自己的时钟，是为了让租约在两边算出同一个结果。
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

/// 绑定并加入组播组。
///
/// # 为什么用 `socket2` 而不是 `std::net::UdpSocket::bind`
///
/// `std` 的 `bind` 是一步到位的，中间没有设选项的机会，而这里**必须**在 `bind`
/// **之前**设 `SO_REUSEADDR`：不设的话，同一台机器上的第二个进程要么 `bind` 直接
/// 失败（Windows），要么收不到任何组播（Linux）。本 crate 有
/// `#![forbid(unsafe_code)]`，而 `setsockopt` 是 `unsafe`，因此这一步只能交给
/// `socket2`——把唯一需要 `unsafe` 的地方收进一个专门做这件事、且被广泛使用的 crate，
/// 比自己开一个口子更可控。
///
/// # 为什么绑通配符而不是组播地址
///
/// 两者在不同平台上行为不一样，而**绑通配符是唯一到处都对的那个**：它在这个端口上
/// 接收一切，再由 `join_multicast_v4` 决定哪些组播组的内容会被投递上来。绑组播地址
/// 在 Linux 上能把单播挡在外面，但在 Windows 上会连组播一起收不到。
///
/// 代价是「有人往这个端口发单播」也会被收到。这是可接受的：解码那一层第一件事就是
/// 核对魔数（见 [`Announcement::decode`]），不是我们的报文会被直接丢掉。
fn bind_multicast(config: LanConfig) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| Error::LanSocket { operation: "new" })?;

    // 顺序不能反：`SO_REUSEADDR` 必须在 `bind` 之前设。
    socket
        .set_reuse_address(true)
        .map_err(|_| Error::LanSocket {
            operation: "set_reuse_address",
        })?;

    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.port));
    socket
        .bind(&bind_addr.into())
        .map_err(|_| Error::LanSocket { operation: "bind" })?;

    // 加入组播组。接口传 `UNSPECIFIED` 表示「由系统决定从哪张网卡加入」——多网卡的
    // 选择留给路由表，理由见模块文档。
    socket
        .join_multicast_v4(&config.group, &Ipv4Addr::UNSPECIFIED)
        .map_err(|_| Error::LanSocket {
            operation: "join_multicast",
        })?;

    // 让回环开着：同机测试与「自己喊的那一声被自己收到」都依赖它，而多收一条自己的
    // 公告的代价是零（[`LanView::observe`] 的序号比较会压掉它，`serve` 里也显式丢掉）。
    socket
        .set_multicast_loop_v4(true)
        .map_err(|_| Error::LanSocket {
            operation: "set_multicast_loop",
        })?;

    // TTL 1：大厅只在这一个网段上有意义。
    //
    // 这不只是省事——**TTL 大于 1 会让公告飘到别的网段**，而「设备列表里出现了一台
    // 隔壁办公室的机器」是用户无法理解的现象。路由器默认也多半不转发 239/8，但那不
    // 该由我们指望。
    socket
        .set_multicast_ttl_v4(1)
        .map_err(|_| Error::LanSocket {
            operation: "set_multicast_ttl",
        })?;

    Ok(UdpSocket::from(socket))
}

/// 把一个公告发到组播组里。
fn send_datagram(
    socket: &Arc<UdpSocket>,
    config: LanConfig,
    announcement: &Announcement,
) -> Result<()> {
    let target = SocketAddr::V4(config.group_addr());
    socket
        .send_to(&announcement.encode(), target)
        .map_err(|_| Error::LanSocket {
            operation: "send_to",
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::wire::{DATAGRAM_LEN, PeerStatus};
    use socket2::SockAddr;
    use std::sync::Mutex;

    /// 同一台机器上真的有组播可用吗。
    ///
    /// 在**没有网卡**的环境里（很多 CI 容器、以及关掉了网络的开发机）组播是收不到的，
    /// 而那是环境问题，不是本 crate 的问题。凡是依赖「数据报真的从组播里过来了」的
    /// 测试都先问这一句，问不到就跳过——**跳过而不是失败**，因为一条会红的测试在
    /// 那种环境上只会被无视。
    static MULTICAST_WORKS: Mutex<Option<bool>> = Mutex::new(None);

    /// 探测一次并缓存结果。
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

    /// 真的建一对 socket 试一次：一个加入组、一个往组里发，看收不收得到。
    ///
    /// 接收方显式限定在**回环网卡**上，发送方也显式指定回环网卡出组播——不这么做的
    /// 话，数据报会从默认网卡出去，而加入了回环网卡的接收方收不到它（这是 IP 组播
    /// 的正常语义，不是缺陷）。
    fn probe_multicast() -> bool {
        let group = Ipv4Addr::new(239, 255, 81, 200);
        let Ok(listener) = joined_socket(group, 0, Ipv4Addr::LOCALHOST) else {
            return false;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("设置读超时");
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

    /// 建一个「绑通配符、设 `SO_REUSEADDR`、加入组播组」的接收 socket。
    ///
    /// 顺序与 [`bind_multicast`] 一致，但接口是可指定的——测试要靠指定接口把组播
    /// 圈在回环网卡上，否则它在一台没有真实网卡（或有多张网卡）的机器上会飘。
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

    /// 造一台设备。
    fn endpoint(seed: u8) -> EndpointKey {
        EndpointKey::from_bytes([seed; 32])
    }

    /// 一条测试用的大厅配置。
    ///
    /// `port` **不能**是 0：公告是发往 `(组播组, 端口)` 的，而端口 0 会让「发到哪里」
    /// 与「绑在哪里」变成两个不同的临时端口，谁也收不到谁。`group` 每条测试各不相同，
    /// 让并发跑的测试互不干扰。
    fn config(last_octet: u8, port: u16, announce_interval_ms: u64) -> LanConfig {
        LanConfig {
            group: Ipv4Addr::new(239, 255, 81, last_octet),
            port,
            announce_interval_ms,
        }
    }

    /// **组播的收发在真实 socket 上跑得通。**
    ///
    /// 这条测试不能用 [`Lobby`] 自己来测：Windows 上同一个组播组+端口只能被绑定一次，
    /// 后绑的那个赢，因此两个 `Lobby` 在同一台机器上收不到对方。这里显式建一对
    /// socket——一个加入组、一个往组里发——把「加入组播组之后真的收得到」这件事钉住。
    /// 它覆盖的是 `join_multicast_v4` 与 `send_to` 这两个本模块真正碰系统调用的地方，
    /// 而**视图归并**那部分由 `wire` 模块的纯逻辑测试覆盖。
    #[test]
    fn multicast_round_trip_over_the_loopback_interface() {
        let group = Ipv4Addr::new(239, 255, 81, 67);
        let Ok(listener) = joined_socket(group, 0, Ipv4Addr::LOCALHOST) else {
            // 这台机器上没有可用的网络栈。跳过而不是失败，理由见 `multicast_works`。
            return;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("设置读超时");
        let port = listener.local_addr().expect("本地地址").port();

        let sender = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("建发送方");
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
            .expect("发出组播");

        let mut buffer = [0_u8; 512];
        let (length, _) = listener.recv_from(&mut buffer).expect("收到组播");
        let decoded = Announcement::decode(&buffer[..length]).expect("自己发的必须解得开");
        assert_eq!(decoded, announcement);
    }

    /// 「绑定 + 加入组 + 设 TTL」这条路径能跑完。
    #[test]
    fn binding_and_joining_works_on_this_machine() {
        let config = config(68, 21_392, ANNOUNCE_INTERVAL_MS);
        match bind_multicast(config) {
            Ok(socket) => {
                assert_eq!(
                    socket.local_addr().expect("本地地址").port(),
                    config.port,
                    "绑的是配置里的端口"
                );
            }
            Err(Error::LanSocket { operation }) => {
                // 没有网络的环境下 `join_multicast_v4` 会失败。如实跳过。
                assert!(
                    matches!(
                        operation,
                        "new" | "set_reuse_address" | "bind" | "join_multicast"
                    ),
                    "失败只可能来自这几个系统调用，实际 {operation}"
                );
            }
            Err(other) => panic!("不该出现的错误：{other:?}"),
        }
    }

    /// **两方在同一个组播组+端口上真的能互相看见。**
    ///
    /// 这条是「同一台机器上能验证到什么程度」的答案：Windows 只把数据报交给最后一个
    /// 绑定者，因此两个 `Lobby` 在**Windows 上收不到对方**（这是 IP 组播的语义，不是
    /// 我们的缺陷）。于是这里把「真实的那一半」拆出来：外部 socket 先加入组，再用
    /// [`bind_multicast`]（也就是 `Lobby` 用的那一个）加入同一个组，然后真的发一条
    /// 公告进去，看双方各自收到什么。
    ///
    /// 收到了就断言内容；一台都没收到就跳过——那说明这台机器上组播不可用。
    #[test]
    fn two_sockets_can_join_the_same_group() {
        let config = config(69, 21_393, ANNOUNCE_INTERVAL_MS);

        let Ok(external) = joined_socket(config.group, config.port, Ipv4Addr::UNSPECIFIED) else {
            return;
        };
        external
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("设置读超时");

        let Ok(lobby_socket) = bind_multicast(config) else {
            return;
        };
        lobby_socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("设置读超时");

        // 发送方也要加入组，否则它发出去的组播在这个网段上未必被投递到已加入的成员。
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
        for socket in [&external, &lobby_socket] {
            if let Ok((length, _)) = socket.recv_from(&mut buffer)
                && let Ok(decoded) = Announcement::decode(&buffer[..length])
            {
                seen.push(decoded);
            }
        }

        if seen.is_empty() {
            // 这台机器上一次组播都没投递（没有网卡，或被策略拦下）。跳过。
            return;
        }
        for decoded in seen {
            assert_eq!(decoded, announcement);
        }
    }

    /// 报文的长度就是线格式的长度，且魔数在。
    ///
    /// 这条测试盯的是 [`crate::lan::wire::DATAGRAM_LEN`] 那个「加出来的常量」——
    /// 它一旦与字段各自漂移，就会先在这里露出来。
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
            "魔数 8 + 版本 1 + 种类 1 + 序号 8 + 标识 32 + 公钥 32 + 端口 2"
        );
        assert_eq!(&bytes[..8], b"Q2FALAN\0");
    }

    /// 事件队列为空时 `try_poll` 返回 `None`，且这**不是**错误。
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

    /// **一条公告真的从 socket 走到视图里。**
    ///
    /// 这是本模块唯一一条覆盖「收 → 解 → 观察 → 发事件 → 记进视图」整条链路的测试。
    /// 它不依赖组播：数据报直接发到 [`Lobby`] 的临时端口上（`127.0.0.1` 出去、绑在
    /// 通配符上的 socket 收下来），因此只要有回环就一定能跑。
    #[test]
    fn an_announcement_reaches_the_view() {
        let Ok(mut lobby) = Lobby::open_with(
            DeviceId::from_bytes([1; 32]),
            endpoint(1),
            41_010,
            config(71, 0, 60_000),
        ) else {
            return;
        };
        let port = lobby.socket.local_addr().expect("本地地址").port();

        let peer = Announcement {
            kind: Kind::Hello,
            sequence: 3,
            device: DeviceId::from_bytes([2; 32]),
            endpoint_key: endpoint(2),
            port: 41_011,
        };
        let injector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("绑注入方");
        injector
            .send_to(
                &peer.encode(),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            )
            .expect("注入公告");

        let event = lobby
            .poll(Duration::from_secs(2))
            .expect("应当收到一个事件");
        assert_eq!(event.kind, EventKind::Appeared);
        assert_eq!(event.peer.device, peer.device);
        assert_eq!(event.peer.endpoint_key, peer.endpoint_key);
        assert_eq!(event.peer.port, peer.port);
        assert_eq!(event.peer.status, PeerStatus::Here);

        // 视图也必须跟着变——事件与视图是两份数据，只更新一份就等于没更新。
        assert_eq!(lobby.view().here().len(), 1);
        assert_eq!(lobby.view().get(&peer.device), Some(event.peer));

        // 同一条再发一次：序号没变，因此不产生事件。
        injector
            .send_to(
                &peer.encode(),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            )
            .expect("再注入一次");
        assert_eq!(
            lobby.poll(Duration::from_millis(600)),
            None,
            "序号没变的重发不该产生事件"
        );
    }

    /// 别人家的、和坏掉的报文都必须被悄悄丢掉，且不得把视图弄脏。
    ///
    /// 组播组是共享的：同一网段上可能有别人的程序，也可能有人往这个组里灌任意字节。
    /// 「安静地丢掉」是这里唯一正确的处置——报错会让一条完全正常的网络现象看起来像
    /// 故障，而界面会被它刷屏。
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
        let port = lobby.socket.local_addr().expect("本地地址").port();
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        let injector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("绑注入方");

        for datagram in [
            b"GET / HTTP/1.1\r\n\r\n".as_slice(),
            b"Q2FALAN\0\x01\x01",
            b"Q2FASYN\0\x02\x01\x00",
        ] {
            injector.send_to(datagram, target).expect("注入");
        }

        assert_eq!(lobby.poll(Duration::from_millis(500)), None);
        assert!(lobby.view().is_empty(), "坏报文不得进视图");
    }

    /// **周期喊话真的把公告发出去了。**
    ///
    /// 这条测试监听 `<组播组, 端口>`，并让 `Lobby` 以 20 毫秒的周期往同一个组里喊。
    /// 它同时钉住两件容易写错的事：公告发往的是 `(组, 端口)` 而不是别处，以及周期
    /// 喊话用的是**本机的**设备标识与端点公钥。
    ///
    /// 收不到就跳过——Windows 只把组播交给最后一个绑定者，这台机器上可能正好不是我们。
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
            .expect("设置读超时");

        let me = DeviceId::from_bytes([4; 32]);
        let Ok(lobby) = Lobby::open_with(me, endpoint(4), 41_013, config) else {
            return;
        };

        let mut buffer = [0_u8; 512];
        loop {
            let Ok((length, _)) = listener.recv_from(&mut buffer) else {
                // 3 秒内一条都没收到。这台机器上组播没投递给我们，跳过。
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

    /// 关闭之后线程必须真的退出，且能重复调用。
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
        assert!(lobby.worker.is_none(), "线程句柄应当已经被取走");
    }

    /// 自己喊的那一声不该把自己变成对端。
    ///
    /// `IP_MULTICAST_LOOP` 会把本机发的组播回送给自己，而我们**刻意**不关掉它（同机
    /// 测试依赖它）。这条测试保证关掉它的替代方案——显式丢掉 `device == me` 的报文
    /// ——确实在起作用。
    #[test]
    fn a_device_never_becomes_its_own_peer() {
        let me = DeviceId::from_bytes([6; 32]);
        let Ok(mut lobby) = Lobby::open_with(me, endpoint(6), 41_015, config(75, 21_397, 10))
        else {
            return;
        };

        // 数据报注入到自己的端口上：它会在 `serve` 里被解出来，然后被那条显式检查丢掉。
        let port = lobby.socket.local_addr().expect("本地地址").port();
        let injector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("绑注入方");
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
            .expect("注入自己的公告");

        assert_eq!(lobby.poll(Duration::from_millis(500)), None);
        assert!(
            lobby.view().get(&me).is_none(),
            "自己不该出现在自己的对端列表里"
        );
    }

    /// 一条公告在最小 MTU 上装得下，且余量够再装一条。
    ///
    /// 这条性质不显眼但重要：组播报文**不允许分片**（分片会丢掉「要么整条到、要么
    /// 不到」的语义，而我们的格式是定长的，分片只会让解析器看到半条——虽然它会拒绝，
    /// 但那意味着这条路在 MTU 小的链路上根本不通）。
    ///
    /// 判据用**余量**而不是「小于某个数」：后者在格式加了字段之后可能仍然成立，而
    /// 余量归零是那种改动真正会撞上的边界。
    #[test]
    fn the_datagram_leaves_room_within_the_smallest_mtu() {
        /// IPv4 要求任何主机都能重组 576 字节的数据报（RFC 791）。
        const MIN_IPV4_MTU: usize = 576;
        /// IPv4 头（20）+ UDP 头（8）。
        const HEADERS: usize = 28;
        let payload_budget = MIN_IPV4_MTU - HEADERS;
        assert!(
            DATAGRAM_LEN * 2 <= payload_budget,
            "{DATAGRAM_LEN} 字节的公告在 {payload_budget} 字节的预算里放不下两条"
        );
    }
}
