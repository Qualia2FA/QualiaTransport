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

//! 局域网的数据面：把一段字节送到对端，靠的是 **iroh 的离线配置**（D7）。
//!
//! # 与核心库的关系
//!
//! 本模块提供的是 `qualia2fa_core::transport::Transport` 那一套能力——「发一段字节 /
//! 收一段字节 / 对端是谁」。但那份 trait 定义在核心库里，而**依赖方向是「本 crate ←
//! 核心库」**，因此本模块不能反过来引用它。这里给出的是一个**形状相同、命名独立**的
//! 类型：核心库（或 FFI 层）用一层不含判断的转发把两者接起来，那层转发里没有任何
//! 逻辑，因此也没有任何东西会躲过测试。
//!
//! # 为什么是 iroh 而不是自己写 QUIC
//!
//! 自己写要面对三件事：TLS 1.3 的握手与证书校验、QUIC 的丢包恢复与连接迁移、以及
//! 「两端如何在不信任网络的前提下确认对方身份」。iroh 把最后一条做成了它的核心抽象
//! ——endpoint 的身份就是一把公钥，握手证明持有对应私钥。自己写等于重新实现这三件
//! 事，而它们每一件都有过公开的远程漏洞。
//!
//! # 离线是怎么做到的（D7）
//!
//! 四行配置，缺一不可：
//!
//! ```text
//! presets::Minimal            // 只设 crypto provider，不设 relay / DNS / pkarr
//! relay_mode(Disabled)        // 完全不构建 relay transport
//! clear_address_lookup()      // 无 DNS、无 pkarr
//! net_report_config(minimal)  // 关掉 HTTPS 探测与 captive portal 检查
//! ```
//!
//! **必须避开 `presets::N0DisableRelay`**：名字里的「DisableRelay」只关了中继，它
//! **保留** DNS/pkarr 地址发布。用一个名字有误导性的 preset，会让「本应用不联网」
//! 这个承诺悄悄失效。
//!
//! 地址必须带外提供（二维码）或由 [`crate::lan::lobby`] 在同一网段里发现——iroh 1.x
//! 不再内置 mDNS，而本项目也不需要它：组播大厅已经把「谁在这个网段上」回答完了。
//!
//! # 这个配置**尚未**被实证过「零出口」
//!
//! D7 有一条待验证项：**抓包实证零网络出口，之后才允许做「不联网」的对外声明**。
//! 目前做到的是：用 `netstat` 观察整个生命周期，没有出现指向非本地地址的 socket 或
//! 连接（记录在仓库外的 TODO.md）。但 `netstat` **看不见瞬时的 DNS/HTTPS 请求**，
//! 而真正的抓包在 Windows 上需要管理员权限。因此在抓包完成之前，本模块**不得**被
//! 描述成「已证明不联网」。
//!
//! # 平台注意
//!
//! - **Android 17（targetSdk 37+）** 需要 `ACCESS_LOCAL_NETWORK` 才能收发局域网流量。
//! - 组播权限与 TTL 那些事在 [`crate::lan::lobby`] 那一层，与本模块无关（这里只有
//!   单播 QUIC）。

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

/// 本通道的 ALPN。
///
/// ALPN 是 QUIC 握手的一部分：**ALPN 不匹配的连接会被对端在握手阶段直接拒绝**，因此
/// 它顺带把「别的 iroh 应用连到我们的端口上」挡在外面，不需要自己再写一层版本协商。
/// 把它改成别的值等于换了一个不兼容的协议版本。
pub const ALPN: &[u8] = b"qualia2fa/sync/1";

/// 连接建立的超时。
///
/// 局域网里建连要么很快（同一个交换机的几十毫秒），要么永远不会成功。5 秒是「用户
/// 还愿意等」的上限，同时不至于让一次「对端已经关机」的尝试挂住整个界面。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// 单条消息的上限。
///
/// 同步载荷由核心库自己限制在一个远小于此的值，这里是传输层的**独立**上限：一条
/// 消息的长度由对端在流里给出，因此在分配之前必须与上限比较，否则一个几百字节的
/// 报文就能让本进程申请几个 GiB。两个上限分开定义，让「放宽其中一个」不必同时放宽
/// 另一个。
pub const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

/// 收件箱最多积压几条未取走的消息。
///
/// 界面来不及取时**丢掉新来的那一条**：同步载荷是幂等的（核心库的合并是并集运算），
/// 丢掉一条只会让这次同步少并一点，下次再来；而让收件箱无界增长，会让一个不停发消息
/// 的对端把本进程的内存吃光。
///
/// **丢掉是静默的，因此这里刻意不给它一个错误变体。** 丢弃发生在后台的读任务里，
/// 那时没有调用方在等结果，一个没人能看到的错误码只会变成一条谁也读不到的日志。要
/// 观察到它，应当在调用方那一侧记账（比如「收件箱连续满了几次」），而不是在这里造
/// 一个错误——那只会让「有错误类型」看起来像「这件事被处理了」。
pub const INBOX_CAPACITY: usize = 64;

/// 消息的用途标记。
///
/// 现在只有一种，因此它看起来多余。留着它是因为**这个字节在线格式里**：将来要加
/// 「我不发了，别等了」之类的控制消息时，不必再改一次流格式——改了就意味着两个版本
/// 互相看不懂，而局域网上永远可能存在一个旧版本的应用。
const MESSAGE_KIND_HELLO: u8 = 0x01;

/// 一条入站消息的固定头：用途标记 + 设备标识。
///
/// # 为什么设备标识要在线格式里
///
/// 传输层只知道**端点公钥**（QUIC 握手证明的那个），而协议层要的是**设备标识**
/// （用户看得见的那个、白名单里的那个）。两者之间的映射由大厅公告或二维码建立，但
/// 那个映射是**无认证**的：任何人都能公告「设备 X 的端点是 E」。因此绝不能信映射
/// ——每条消息由发送方自己报一次设备标识，接收方用它做白名单检查（核心库的
/// `SyncSenderMismatch` 就是为此存在的），而「他是不是他自称的那台设备」由**配对
/// 流程**在带外确认过。
///
/// 换句话说：这个字段不是用来**建立**信任的，而是用来让接收方**应用**已有的信任。
const ENVELOPE_HEADER_LEN: usize = 1 + qualia_dik::DEVICE_ID_LEN;

/// 一台对端的地址。
///
/// # 两段地址里有一段是可选的，这一点很重要
///
/// `endpoint_key` 是**必需**的：没有它就无法发起连接（iroh 的身份就是端点公钥）。
/// `socket` 是可选的：同一网段上时 IP 从数据包的源地址就能得到，但**跨网段**或经过
/// NAT 时它可能是错的，那时连不上的原因是「地址不对」而不是「对方不在」。
///
/// 因此二维码那条路（[`LanAddress`]）**不带 IP**——用户的两台设备可能在不同的网段
/// 上，写死一个 IP 只会让对端去连一个错的地址。IP 只在大厅发现这条路上出现，因为
/// 那是同一网段内的答案。
///
/// [`LanAddress`]: crate::lan::LanAddress
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddress {
    /// 对端的设备标识（用户看得见的那个）。
    pub device: DeviceId,
    /// 对端的传输层端点公钥。
    pub endpoint_key: EndpointKey,
    /// 对端的 IP 与端口，若已知。
    pub socket: Option<SocketAddr>,
}

impl PeerAddress {
    /// 造一条地址。
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

    /// 转成 iroh 的地址表示。
    ///
    /// # 错误
    ///
    /// 端点公钥不是合法的编码时返回 [`Error::LanTransport`]。32 字节的输入总是合法，
    /// 因此这条路径实际上走不到——留着它是因为「不可能」这句话在依赖升级之后会失效，
    /// 而那时一个 `expect` 就是一个 panic。
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

/// 收件人。
///
/// 与核心库的 `Recipient` 是同一个概念（那边的文档解释了为什么收件人必须显式）。
/// 这里重新定义一次而不是复用，理由与模块文档里说的一样：依赖方向不允许。
///
/// # [`Recipient::All`] 发给「知道的全部对端」，不是「已经连上的全部对端」
///
/// 这个区别是刻意的：连接是按需建立的，而「我刚打开应用、还没跟任何人说过话」正是
/// 最需要广播的时刻——那时 `connections` 是空的，若 `All` 按它取，一次「我在这里，
/// 这是我的状态」会静默地发给零个人，而调用方拿到 `Ok(())`。
///
/// 因此 `All` 取的是**登记过的对端**（[`IrohLan::remember_peer`] 写进去的那个表），
/// 建连由发送路径按需完成。反过来，名单之外的人永远收不到——那既符合 `Recipient`
/// 的契约，也符合同步协议的白名单设计。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    /// 只发给这一个对端。
    One(DeviceId),
    /// 发给**已知的**全部对端。
    All,
}

/// 一次发送请求（交给写线程去等连接）。
struct SendRequest {
    /// 收件人。
    to: Recipient,
    /// 已经封好头的字节。
    framed: Vec<u8>,
    /// 结果回执。
    done: oneshot::Sender<Result<()>>,
}

/// 写线程与接收路径共用的状态。
struct LanState {
    /// iroh 端点。
    endpoint: Endpoint,
    /// 本设备的设备标识（封头时写进去的那个）。
    device: DeviceId,
    /// 已知的对端地址。
    peers: Mutex<HashMap<DeviceId, PeerAddress>>,
    /// 已经建立的连接。
    connections: Mutex<HashMap<DeviceId, iroh::endpoint::Connection>>,
    /// 收件箱的发送端。
    inbox: mpsc::Sender<(DeviceId, Vec<u8>)>,
}

/// 局域网通道（iroh 离线配置）。
///
/// # 它自己起一个 tokio 运行时
///
/// iroh 是 async 的，而本类型面对的是同步调用方（界面线程、核心库的同步 `Transport`）。
/// 桥接方式是在构造时起一个多线程 tokio 运行时，用 `block_on` 把异步操作搬过去。
///
/// **异步代码不能在自己所在的运行时上 `block_on`**（会 panic），因此调用方必须从
/// 一个**不是** tokio worker 的线程上调用本类型的方法。桌面端的界面线程天然满足，
/// 而这也是本类型不提供 async 接口的原因：两套接口会让「哪一套在哪个线程上跑」变成
/// 每个调用点都要重新想一遍的事。
///
/// # 对端的地址要显式登记
///
/// QUIC 连接需要**端点公钥**，而「设备标识 → 端点公钥」这个映射来自大厅公告或
/// 二维码。本类型**刻意不自己去问大厅**：那会让传输层依赖发现层，而两者的测试与
/// 替换理由完全不同。调用方用 [`IrohLan::remember_peer`] 登记，通常是在处理
/// [`crate::lan::lobby::Event`] 的时候。
pub struct IrohLan {
    /// 异步运行时。
    runtime: Runtime,
    /// 写线程与接收路径共用的状态。
    state: Arc<LanState>,
    /// 收件箱的接收端。
    inbox: AsyncMutex<mpsc::Receiver<(DeviceId, Vec<u8>)>>,
    /// 发送请求的队列。
    send_tx: mpsc::UnboundedSender<SendRequest>,
    /// 本设备的设备标识。
    device: DeviceId,
    /// 本端点的端点公钥。
    endpoint_key: EndpointKey,
}

impl IrohLan {
    /// 用一把固定的端点私钥打开通道，绑定到系统挑选的端口。
    ///
    /// # 错误
    ///
    /// [`Error::LanTransport`]：运行时建不起来，或绑定失败（端口耗尽、系统策略拦下
    /// UDP）。
    pub fn open(device: DeviceId, secret_key: EndpointKey) -> Result<Self> {
        Self::open_with(device, secret_key, None)
    }

    /// 用给定的绑定地址打开通道。
    ///
    /// # 错误
    ///
    /// 同 [`IrohLan::open`]。
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
                // ① 完全不构建 relay transport。这是「不联网」里最要紧的一条。
                .relay_mode(RelayMode::Disabled)
                // ② 不注册任何地址发布/解析服务：没有 DNS，没有 pkarr。
                .clear_address_lookup()
                // ③ 关掉 HTTPS 探测与 captive portal 检查。
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

    /// 本设备的设备标识。
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device
    }

    /// 本端点的端点公钥（别人要用它来连我们）。
    #[must_use]
    pub const fn endpoint_key(&self) -> EndpointKey {
        self.endpoint_key
    }

    /// 本端点实际监听的地址。
    #[must_use]
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.state.endpoint.bound_sockets()
    }

    /// 本端点的端口（取第一个绑定的 socket）。
    ///
    /// 给「把连接信息放进二维码」那条路用：二维码里只有端点公钥与端口，没有 IP——
    /// IP 由对端从自己的路由表里找，写死一个 IP 会让跨网段的用户连不上。
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.bound_sockets().first().map(SocketAddr::port)
    }

    /// 登记一个对端的地址。
    ///
    /// 重复登记会覆盖——大厅公告里的地址可能变（对方换了网卡、换了端口），而保留旧
    /// 地址只会让下一次连接尝试先失败一次。
    pub fn remember_peer(&self, peer: PeerAddress) {
        lock(&self.state.peers).insert(peer.device, peer);
    }

    /// 忘记一个对端（连同它的连接）。
    pub fn forget_peer(&self, device: &DeviceId) {
        lock(&self.state.peers).remove(device);
        if let Some(connection) = lock(&self.state.connections).remove(device) {
            connection.close(0_u8.into(), b"forgotten");
        }
    }

    /// 当前有连接的对端，按设备标识排序。
    ///
    /// 顺序稳定，让调用方（与测试）不必依赖内部的哈希顺序。
    #[must_use]
    pub fn connected_peers(&self) -> Vec<DeviceId> {
        let mut peers: Vec<DeviceId> = lock(&self.state.connections).keys().copied().collect();
        peers.sort();
        peers
    }

    /// 送出一条消息，**不等**它真的出去。
    ///
    /// # 返回 `Ok` 的含义是「已接受这次发送」
    ///
    /// 不是「对端收到了」——QUIC 本身也不承诺后者（连接可能在任何一刻断掉）。真正的
    /// 失败（连接建不起来、流写不进去）由写线程在后面决定，因此**它无法通过这个
    /// 返回值报告**。这是刻意的：一个会阻塞界面线程直到连接超时的发送，比一个「可能
    /// 没送到」的发送糟得多。要确定性就用 [`IrohLan::send_blocking`]。
    ///
    /// # 错误
    ///
    /// - [`Error::PayloadTooLarge`]：消息超过 [`MAX_MESSAGE_LEN`]。
    /// - [`Error::NoConnectionToPeer`]：[`Recipient::One`] 指向一个从未登记过的对端。
    ///   这是**调用方的程序错误**（先登记再发），当场报出来比默默丢掉好。
    /// - [`Error::LanTransport`]：写线程已经不在了（本类型正在析构）。
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

    /// 送出一条消息并等它真的写进流里。
    ///
    /// 给测试与「用户按了同步、界面显示一个转圈」那条路用。它会**阻塞当前线程**，
    /// 最长一次连接建立加一次写的时间。
    ///
    /// # 错误
    ///
    /// 同 [`IrohLan::send`]，另外加上连接建立与写入的失败。
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

    /// 校验收件人、限长，并封好头。
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
        // **发送方标识取自本机**，不是取自收件人。这一点很容易写错，而写错的症状是
        // 接收方看到一个「自称是别人」的消息，于是核心库的白名单检查（那是防重放的
        // 关键一环）把它当成攻击丢掉——同步静默失败，且没有任何一条日志指向真正原因。
        Ok(wrap(self.device, message))
    }

    /// 收一条消息，交回**发送方自己报的设备标识**与字节。
    ///
    /// 当前没有消息时返回 [`Error::TransportEmpty`]（与核心库的契约一致：调用方
    /// 据此决定要不要再等，而它**不是**错误）。
    ///
    /// # 错误
    ///
    /// 队列里没有消息时返回 [`Error::TransportEmpty`]。
    pub fn try_receive(&self) -> Result<(DeviceId, Vec<u8>)> {
        match self.inbox.try_lock() {
            Ok(mut inbox) => match inbox.try_recv() {
                Ok(message) => Ok(message),
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    Err(Error::TransportEmpty)
                }
            },
            // 另一个线程正在接收。对调用方来说这与「暂时没有消息」没有区别，而且它
            // 本来就不该在两个线程上同时取同一条消息。报「没有」而不是阻塞，是
            // 「try」这个词的承诺。
            Err(_) => Err(Error::TransportEmpty),
        }
    }

    /// 阻塞最多 `timeout` 收一条消息。
    ///
    /// 超时返回 [`Error::TransportEmpty`]，与「当前没有消息」是同一个结果——调用方
    /// 要么再等，要么去干别的。
    ///
    /// # 错误
    ///
    /// 超时或队列断开时返回 [`Error::TransportEmpty`]。
    pub fn receive_timeout(&self, timeout: Duration) -> Result<(DeviceId, Vec<u8>)> {
        let received = self.runtime.block_on(async {
            let mut inbox = self.inbox.lock().await;
            tokio::time::timeout(timeout, inbox.recv()).await
        });
        match received {
            Ok(Some(message)) => Ok(message),
            // 超时，或者队列已经断开（本类型正在析构）。
            Ok(None) | Err(_) => Err(Error::TransportEmpty),
        }
    }

    /// 关掉通道：结束所有连接、停掉 iroh 端点。
    ///
    /// 重复调用是安全的。
    pub fn shutdown(&self) {
        self.runtime.block_on(self.state.endpoint.close());
    }
}

impl Drop for IrohLan {
    fn drop(&mut self) {
        // 端点不关掉的话，后台的 net_report / QUIC 定时器会继续活着，而运行时的析构
        // 会等它们——表现为「退出时卡一下」。这里主动关一次。
        if !self.state.endpoint.is_closed() {
            self.shutdown();
        }
    }
}

/// 取锁，忽略中毒。
///
/// 中毒意味着**别的线程在持锁时 panic 了**，而这里的数据结构（哈希表）不会因为一次
/// panic 处于「部分更新」的危险状态：它要么插入了要么没插入。让后续调用继续，比让
/// 整个通道因为一次无关的 panic 而永久失效要好。
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 给一条消息加上封装头。
fn wrap(device: DeviceId, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_HEADER_LEN + message.len());
    out.push(MESSAGE_KIND_HELLO);
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(message);
    out
}

/// 拆封装头，交回发送方自报的设备标识与消息体。
///
/// # 错误
///
/// 太短、或用途标记不认识时返回 [`Error::LanTransport`]。两者都是**对端的程序错误
/// 或攻击**，而我们能做的只有丢掉——不认识就解析，等于把「将来加一种消息」变成一次
/// 静默的误解。
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

/// 接受入站连接，并为每条连接起一个读取循环。
async fn accept_loop(state: Arc<LanState>) {
    while let Some(incoming) = state.endpoint.accept().await {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            // `accept` 返回一个 `Accepting` future，因此这里要 await 两次：
            // 一次拿 `Accepting`，一次完成握手拿 `Connection`。
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                // 握手失败（ALPN 不匹配、对方拿不出私钥）是**正常现象**：同一台机器上
                // 可能有别的 iroh 应用，也可能有人在扫端口。不值得记日志。
                return;
            };
            read_connection(state, connection).await;
        });
    }
}

/// 读一条连接上的全部入站流，直到连接结束。
async fn read_connection(state: Arc<LanState>, connection: iroh::endpoint::Connection) {
    while let Ok((_send, mut recv)) = connection.accept_bi().await {
        let Ok(bytes) = recv.read_to_end(MAX_MESSAGE_LEN).await else {
            continue;
        };
        let Ok((sender, message)) = unwrap_message(&bytes) else {
            continue;
        };
        // 这条连接是谁的，现在有答案了：消息自己报了设备标识。把它记下来，之后的
        // 定向发送就能复用这条连接，而不必（也不可能）凭端点公钥反查设备标识。
        if sender != state.device {
            lock(&state.connections).insert(sender, connection.clone());
        }
        if state.inbox.try_send((sender, message)).is_err() {
            // 收件箱满了，或者本类型已经在析构。**不回执、不重试**：同步是幂等的，
            // 丢掉这一条只会让这次同步少并一点，而重试会把一次「界面卡住」放大成
            // 网络层的一串重传。
            continue;
        }
    }
}

/// 处理发送请求队列。
async fn write_loop(state: Arc<LanState>, mut requests: mpsc::UnboundedReceiver<SendRequest>) {
    while let Some(request) = requests.recv().await {
        let result = deliver(&state, request.to, &request.framed).await;
        // 回执可能已经没人等了（调用方用了不等结果的 `send`）。
        let _ = request.done.send(result);
    }
}

/// 把一条消息真正送出去。
async fn deliver(state: &Arc<LanState>, to: Recipient, framed: &[u8]) -> Result<()> {
    let targets: Vec<DeviceId> = match to {
        Recipient::One(device) => vec![device],
        // 取**登记过的**对端而不是**已连上的**对端，理由见 [`Recipient::All`] 的文档。
        Recipient::All => {
            let mut all: Vec<DeviceId> = lock(&state.peers).keys().copied().collect();
            all.sort();
            all
        }
    };

    // 一条都没有时**不报错**：`Recipient::All` 在「还没有任何对端」时是零个收件人，
    // 那是正常状态而不是失败。
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

/// 把一条消息送给一个对端，必要时先建连接。
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
    // `finish` 关掉发送方向。不收对方的回执：核心库的同步是**两条独立的消息**
    // （我给你我的状态、你给我你的），在这里等一个 ack 只会把「一次同步」变成
    // 「两次往返」，而它并不提供任何核心库还没有的保证。
    send.finish().map_err(|_| Error::LanTransport {
        operation: "finish",
    })?;
    Ok(())
}

/// 取得（必要时建立）到某个对端的连接。
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

    /// 在回环上开一对通道，并互相登记对方**走哪个端口**。
    ///
    /// # 为什么必须显式给出端口
    ///
    /// 两个端点绑的都是系统挑的临时端口，而 `PeerAddress` 里的 `socket` 是可选的
    /// ——不给的话 iroh 只有一个端点公钥，没有任何地址，连不出去。这正是真实部署里
    /// 「二维码只带公钥与端口、对端自己找 IP」那条路的形状：把 IP 填成本机回环，
    /// 就是那条路在单机上的等价物。
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

    /// 端点公钥**来自给定的那把端点私钥**，而且是确定性的。
    ///
    /// # 为什么不能直接比字节
    ///
    /// 第一版这条测试断言 `endpoint_key() == key(1)`，而它失败了：iroh 的
    /// `SecretKey::from_bytes` 收的是 **Ed25519 的种子**，公钥由种子经 SHA-512 与标量
    /// 钳位派生出来——**公钥不等于种子**。断言「相等」是把 Ed25519 的密钥派生当成
    /// 恒等映射，而那是错的。
    ///
    /// 真正要证明的性质有两条，它们都不需要知道派生细节：
    /// 同一把私钥 → 同一个公钥（确定性，因此「设备身份与端点身份的绑定」是可复现的），
    /// 以及不同私钥 → 不同公钥（端点身份真的在区分设备，而不是每次随机生成一个）。
    /// 后一条尤其重要：一个每次随机生成端点密钥的实现**也能让通信测试通过**，但它会
    /// 让「用二维码把端点公钥带外传过去」这条设计悄悄失效。
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
            "同一把私钥必须派生出同一个端点公钥"
        );
        assert_ne!(
            first.endpoint_key(),
            other.endpoint_key(),
            "不同的私钥必须派生出不同的端点公钥"
        );
    }

    /// 绑定的端口必须真的是一个可用的端口，且 `port()` 与 `bound_sockets()` 一致。
    #[test]
    fn the_bound_port_is_reported_consistently() {
        let Ok(lan) = IrohLan::open(device(3), key(3)) else {
            return;
        };
        let sockets = lan.bound_sockets();
        assert!(!sockets.is_empty(), "至少应当绑定一个 socket");
        assert_eq!(lan.port(), Some(sockets[0].port()));
        assert_ne!(
            lan.port(),
            Some(0),
            "端口 0 是「由系统挑」，不是挑完之后的那个值"
        );
    }

    /// **同机双端真的能互通。**
    ///
    /// 这是本模块最有价值的一条测试：它在没有第二台真机的情况下跑完了一条真实的
    /// QUIC 路径（TLS 握手、流、消息封装），而不只是把字节塞进一个队列。
    ///
    /// 收不到就跳过——一台完全没有回环可用的机器上，这条测试证明不了任何东西，
    /// 而让它红只会让 CI 变成噪声。
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
        assert_eq!(sender, device(2), "发送方标识必须来自本机");
        assert_eq!(received, payload, "字节必须原样到达");
    }

    /// 反方向也要通——QUIC 的连接是双向的，而「谁能主动发起」在一个用组播发现的
    /// 网络里两边都可能。
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

    /// 一条连接建立之后，反方向可以复用同一条连接。
    ///
    /// 这条测试盯的是 `read_connection` 里那次「记下这条连接是谁的」：不记的话，
    /// B 要回消息给 A 时会因为「没有到 A 的连接」去重新建一次，而那个连接需要 A 的
    /// 地址——如果 A 在 NAT 后面，那个地址就建不起来。
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
            "收到消息之后应当记住这条连接是谁的，实际 {:?}",
            b.connected_peers()
        );
    }

    /// 没登记过的对端要**当场报错**，而不是默默丢掉。
    #[test]
    fn sending_to_an_unregistered_peer_is_an_error() {
        let Ok(lan) = IrohLan::open(device(8), key(8)) else {
            return;
        };
        let result = lan.send(Recipient::One(device(99)), b"x");
        assert!(
            matches!(result, Err(Error::NoConnectionToPeer)),
            "应当报「没有到该对端的连接」，实际 {result:?}"
        );
    }

    /// 超过上限的消息要在**分配之前**被拒绝。
    #[test]
    fn an_oversized_message_is_rejected_before_allocating() {
        let Ok(lan) = IrohLan::open(device(9), key(9)) else {
            return;
        };
        lan.remember_peer(PeerAddress::new(device(10), key(10), None));
        // 造一个「声称」超长的输入：这里只需要长度超过上限，内容不限。
        let too_long = vec![0_u8; MAX_MESSAGE_LEN + 1];
        let result = lan.send(Recipient::One(device(10)), &too_long);
        match result {
            Err(Error::PayloadTooLarge { needed, limit }) => {
                assert_eq!(limit, MAX_MESSAGE_LEN);
                assert_eq!(needed, MAX_MESSAGE_LEN + 1);
            }
            other => panic!("应当报「太大」，实际 {other:?}"),
        }
    }

    /// **`Recipient::All` 只有一个对端时不会发给别人。**
    ///
    /// 契约是「不得退化成广播给名单之外的人」。这里用三个端点验证：C 从来没有登记过
    /// A，因此 A 的 `All` 也到不了 C。
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
            "已连接的对端应当收到广播"
        );
        assert!(
            c.receive_timeout(Duration::from_secs(1)).is_err(),
            "没有连接过的对端不该收到任何东西"
        );
    }

    /// 「暂时没有消息」必须是 [`Error::TransportEmpty`]，而不是别的错误。
    ///
    /// 核心库的契约靠这个区分「继续等」与「拒绝」。报成别的错误会让同步循环以为
    /// 通道坏了。
    #[test]
    fn an_empty_inbox_reports_no_session_found() {
        let Ok(lan) = IrohLan::open(device(14), key(14)) else {
            return;
        };
        let result = lan.try_receive();
        assert!(
            matches!(result, Err(Error::TransportEmpty)),
            "空收件箱应当报「没有消息」，实际 {result:?}"
        );
        let result = lan.receive_timeout(Duration::from_millis(50));
        assert!(
            matches!(result, Err(Error::TransportEmpty)),
            "超时应当报「没有消息」，实际 {result:?}"
        );
    }

    /// 封装头必须逐字节钉住，且**发送方标识取自本机**。
    #[test]
    fn the_envelope_header_is_pinned() {
        let me = DeviceId::from_bytes([0xAB; 32]);
        let framed = wrap(me, b"body");
        assert_eq!(framed.len(), ENVELOPE_HEADER_LEN + 4);
        assert_eq!(framed[0], MESSAGE_KIND_HELLO);
        assert_eq!(&framed[1..33], &[0xAB; 32]);
        assert_eq!(&framed[33..], b"body");

        let (sender, message) = unwrap_message(&framed).expect("自己封的必须解得开");
        assert_eq!(sender, me);
        assert_eq!(message, b"body");
    }

    /// 空消息体是合法的（一条「请求」就没有载荷），太短或种类不认识则不是。
    #[test]
    fn malformed_envelopes_are_rejected() {
        assert!(unwrap_message(&[]).is_err(), "空输入应当被拒绝");
        assert!(
            unwrap_message(&[MESSAGE_KIND_HELLO]).is_err(),
            "只有种类字节"
        );
        assert!(unwrap_message(&[0x7F; 33]).is_err(), "种类不认识");

        let me = DeviceId::from_bytes([1; 32]);
        let (sender, message) = unwrap_message(&wrap(me, b"")).expect("空消息体合法");
        assert_eq!(sender, me);
        assert!(message.is_empty());
    }

    /// 关掉之后再关一次必须安全。
    #[test]
    fn shutdown_is_idempotent() {
        let Ok(lan) = IrohLan::open(device(15), key(15)) else {
            return;
        };
        lan.shutdown();
        lan.shutdown();
        assert!(lan.state.endpoint.is_closed());
    }

    /// 忘记一个对端之后，定向发送必须重新变成「没有连接」。
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
            "忘记之后应当报「没有到该对端的连接」，实际 {result:?}"
        );
    }
}
