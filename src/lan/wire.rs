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

//! 局域网大厅的**线格式**：谁在这个网段上、用什么地址连接他。
//!
//! # 格式（版本 1）
//!
//! 每个报文都是**定长 52 字节**，一律大端：
//!
//! ```text
//! 魔数 8 | 版本 1 | 种类 1 | 序号 8 | 设备标识 32 | 端点公钥 32 | 端口 2
//! ```
//!
//! | 段 | 内容 | 为什么是它 |
//! |----|------|-----------|
//! | 魔数 | `Q2FALAN\0` | 组播组是共享的，第一件事必须是「这是不是我们的报文」 |
//! | 版本 | `1` | 单独一段，好让「版本比本机新」与「这不是我们的报文」分开报 |
//! | 种类 | [`Kind`] | 见下 |
//! | 序号 | 每台设备自己的计数器 | 压掉组播路径上的乱序与重复投递 |
//! | 设备标识 | [`DeviceId`]（32 字节） | 用户看得见的那个身份，也是白名单用的那个 |
//! | 端点公钥 | [`EndpointKey`]（32 字节） | 传输层真正用来建连、并**由握手认证**的身份 |
//! | 端口 | `u16` | 连到哪个端口 |
//!
//! # 为什么定长
//!
//! 定长让解析器的形状就是「长度不对就拒绝」，没有一处变长解析——而变长解析正是一
//! 个可以被输入牵着走的地方。代价是将来加字段必须换版本号，这个代价是划算的。
//!
//! # 为什么要两个身份字段，而不是一个
//!
//! 「设备标识」与「端点公钥」**不是同一个东西**，混为一谈会丢掉认证：
//!
//! - [`DeviceId`] 是设备身份公钥（P-256，硬件密钥库里的那把）的 SHA-256。它是
//!   **用户看得见**的那个标识，也是同步白名单里的那个值。
//! - [`EndpointKey`] 是传输层（QUIC）的长期密钥，建连时**由握手证明**持有者确实是它。
//!
//! 组播公告是**无认证**的：任何人都能声称自己是任何设备。因此公告只能用来回答
//! 「这个网段上大概有谁、去哪里找他」，**不能**用来回答「他真的是那台设备吗」。后
//! 者由建立连接时的握手（端点公钥）与同步层的白名单（设备标识）回答。把两个字段
//! 都带着，是为了让「公告说什么」与「连接证明什么」可以被**交叉核对**——两者不一致
//! 的连接必须被丢掉，而那是一行显式的检查，不是一句约定。
//!
//! # 为什么不签名
//!
//! 想过给公告签名（用硬件密钥库里的设备身份私钥），放弃了：签名的代价是**每次公告
//! 都要进一次硬件密钥库**，而公告是周期性的（同一个网段上待机时每分钟一次）。一个
//! 为了防「有人伪造存在性」而让 TPM 每分钟被唤醒一次的设计，是在用真实的电池与
//! 性能代价去防一个**连接层本来就挡得住**的攻击：伪造公告只能让对端发起一次连接，
//! 而那次连接会在握手阶段暴露出伪造者拿不出端点私钥。
//!
//! 这也正是 D4 的原则在局域网上的翻版：**发现可以无认证，凭据必须来自信道。**

use qualia_dik::{DEVICE_ID_LEN, DeviceId};

use crate::error::{Error, Result};

/// 大厅报文的魔数。
///
/// 8 字节，末尾留一个 NUL——与核心库的保险库文件、同步载荷同一个约定，好让它在
/// 十六进制编辑器里一眼认得出来。
pub const MAGIC: &[u8; 8] = b"Q2FALAN\0";

/// 线格式版本。
pub const VERSION: u8 = 1;

/// 端点公钥的长度（QUIC 长期密钥是 Ed25519 公钥）。
pub const ENDPOINT_KEY_LEN: usize = 32;

/// 序号的长度。
pub const SEQUENCE_LEN: usize = 8;

/// 报文总长度。
///
/// 由各段长度相加得出，**刻意不写成一个字面量**：手抄的常量在这里已经踩过一次坑
/// （见核心库 `RECORD_HEADER_LEN` 的注释），而加出来的数字不会与字段各自漂移。
pub const DATAGRAM_LEN: usize =
    MAGIC.len() + 1 + 1 + SEQUENCE_LEN + DEVICE_ID_LEN + ENDPOINT_KEY_LEN + 2;

/// 传输层的端点公钥。
///
/// 它是 QUIC 的长期身份，**不是**设备身份（那个是 [`DeviceId`]）。两者的区别见模块
/// 文档；这里只强调一点：这个值可以在轮换端点密钥时变化，而 [`DeviceId`] 不变。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointKey([u8; ENDPOINT_KEY_LEN]);

impl EndpointKey {
    /// 从 32 字节构造。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ENDPOINT_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// 取出原始的 32 字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ENDPOINT_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for EndpointKey {
    /// 只打印前 8 字节。
    ///
    /// 与 [`DeviceId`] 的处理一致：完整公钥没有秘密，但一条日志行里出现两个 32 字节
    /// 十六进制串只会让人读不下去，而排查「这两台设备对上了没有」只需要一个短前缀。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EndpointKey({})", hex8(&self.0))
    }
}

/// 把一段字节的前 8 个字节打成十六进制。
fn hex8(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// 报文的种类。
///
/// # 为什么「离开」这个种类值得单独存在
///
/// 没有它，一台设备被关掉之后仍然会留在别人的对端列表里，直到租约过期。租约必须
/// 足够长（否则网络抖一下就把用户设备从列表里抹掉），因此「用户关掉应用」与「用户
/// 拔了网线」在界面上会长时间长得一样。一条 `Bye` 让前一种情况立刻可见。
///
/// 它**不是**安全机制：任何人都能替别人发 `Bye`，正如任何人都能替别人发 `Hello`。
/// 它的价值是礼貌，不是保证——所以收到 `Bye` 只是把对端标成「已离开」，而不是从
/// 视图里删掉（见 [`LanView::forget`] 与 [`Peer::status`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 我在这里，可以连我。
    Hello,
    /// 我要走了，别等我了。
    Bye,
}

impl Kind {
    /// 线格式里的字节值。
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Hello => 0x01,
            Self::Bye => 0x02,
        }
    }

    /// 从线格式的字节还原。
    #[must_use]
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Bye),
            _ => None,
        }
    }
}

/// 一条公告。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announcement {
    /// 这是「我在这里」还是「我要走了」。
    pub kind: Kind,
    /// 发送方自己的序号，每发一条加一。
    ///
    /// 从 0 开始。它是**每台设备自己的**计数器，不跨设备比较——不同设备的计数器没有
    /// 任何关系，拿它们比大小是没有意义的。
    pub sequence: u64,
    /// 发送方的设备标识。
    pub device: DeviceId,
    /// 发送方的传输层端点公钥。
    pub endpoint_key: EndpointKey,
    /// 发送方监听的端口。
    pub port: u16,
}

impl Announcement {
    /// 编码成 [`DATAGRAM_LEN`] 字节。
    #[must_use]
    pub fn encode(&self) -> [u8; DATAGRAM_LEN] {
        let mut out = [0_u8; DATAGRAM_LEN];
        let mut at = 0;
        out[at..at + MAGIC.len()].copy_from_slice(MAGIC);
        at += MAGIC.len();
        out[at] = VERSION;
        at += 1;
        out[at] = self.kind.as_byte();
        at += 1;
        out[at..at + SEQUENCE_LEN].copy_from_slice(&self.sequence.to_be_bytes());
        at += SEQUENCE_LEN;
        out[at..at + DEVICE_ID_LEN].copy_from_slice(self.device.as_bytes());
        at += DEVICE_ID_LEN;
        out[at..at + ENDPOINT_KEY_LEN].copy_from_slice(&self.endpoint_key.0);
        at += ENDPOINT_KEY_LEN;
        out[at..at + 2].copy_from_slice(&self.port.to_be_bytes());
        out
    }

    /// 从一段字节解出一条公告。
    ///
    /// # 错误
    ///
    /// - [`Error::NotOurDatagram`]：魔数不对。局域网组播组是共享的，同网段上可能
    ///   有别人的程序，也可能有人往这个组里灌任意字节。这一条是**丢弃**，不是故障。
    /// - [`Error::UnsupportedDatagramVersion`]：是我们的报文，但版本比本机新。
    /// - [`Error::UnknownDatagramKind`]：是我们的报文，但种类不认识（多半也是版本新）。
    /// - [`Error::BadDatagramLength`]：长度不是 [`DATAGRAM_LEN`]。
    ///
    /// # 为什么先判魔数再判长度
    ///
    /// 顺序不能反。组播组里绝大多数外来报文都**不是**我们的，先看长度会让它们报成
    /// 「长度不对」——一个听起来像故障、实际上完全正常的结论。先看魔数则让「不是我们
    /// 的」与「是我们的但坏了」在代码里就是两条不同的返回路径。
    pub fn decode(datagram: &[u8]) -> Result<Self> {
        let header = datagram.get(..MAGIC.len()).ok_or(Error::NotOurDatagram)?;
        if header != MAGIC {
            return Err(Error::NotOurDatagram);
        }

        if datagram.len() != DATAGRAM_LEN {
            return Err(Error::BadDatagramLength {
                expected: DATAGRAM_LEN,
                actual: datagram.len(),
            });
        }

        let version = datagram[MAGIC.len()];
        if version != VERSION {
            return Err(Error::UnsupportedDatagramVersion {
                found: version,
                supported: VERSION,
            });
        }

        let kind_byte = datagram[MAGIC.len() + 1];
        let kind =
            Kind::from_byte(kind_byte).ok_or(Error::UnknownDatagramKind { kind: kind_byte })?;

        // 长度已经核对过，因此下面的切片都不会越界。
        let mut at = MAGIC.len() + 2;
        let sequence = read_u64(&datagram[at..at + SEQUENCE_LEN]);
        at += SEQUENCE_LEN;
        let mut device = [0_u8; DEVICE_ID_LEN];
        device.copy_from_slice(&datagram[at..at + DEVICE_ID_LEN]);
        at += DEVICE_ID_LEN;
        let mut endpoint_key = [0_u8; ENDPOINT_KEY_LEN];
        endpoint_key.copy_from_slice(&datagram[at..at + ENDPOINT_KEY_LEN]);
        at += ENDPOINT_KEY_LEN;
        let port = u16::from_be_bytes([datagram[at], datagram[at + 1]]);

        Ok(Self {
            kind,
            sequence,
            device: DeviceId::from_bytes(device),
            endpoint_key: EndpointKey::from_bytes(endpoint_key),
            port,
        })
    }
}

/// 读一个 8 字节大端整数。
fn read_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(bytes);
    u64::from_be_bytes(buf)
}

/// 一个对端在大厅里的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    /// 他在这里。
    Here,
    /// 他发过「我要走了」。
    ///
    /// 这个状态**不等于**「可以把他忘掉」：他可能只是重启了一次，而重启之后的第一条
    /// 公告会把他变回 [`PeerStatus::Here`]。把它单独记下来，是为了让界面能立刻把
    /// 「已关闭的设备」与「断网的设备」分开显示，而不是等租约到期。
    Left,
}

/// 大厅里记住的一个对端。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// 设备标识。
    pub device: DeviceId,
    /// 传输层端点公钥。
    pub endpoint_key: EndpointKey,
    /// 端口。
    pub port: u16,
    /// 最后一次听到的状态。
    pub status: PeerStatus,
    /// 最后一次听到他的时刻（调用方给的毫秒）。
    pub last_seen_ms: u64,
    /// 最后一次听到的序号。
    pub sequence: u64,
}

/// 「这一条公告算不算新消息」。
///
/// 从 [`LanView::observe`] 里拆出来，是为了让这条判断可以被单独测：它是大厅里唯一
/// 一处「谁比谁新」的推理，而这类推理写错的症状是「设备列表偶尔不更新」——很难从
/// 现象回溯到这里。
///
/// # 判据只有序号一个
///
/// `<=` 而不是 `<`：同一个序号重复到达两次是组播路径上的常态（多网卡、多路径、
/// `IP_MULTICAST_LOOP`），第二次不该再触发一轮连接尝试。
///
/// 序号后退意味着**发送方重启了**。这里刻意**不**把它当成新消息——把「序号变小」
/// 当成新消息，等于给重放打开一扇门（录下一条旧公告，等对方序号推进后再放出去）。
/// 代价是重启过的设备要等序号重新爬过水位才会再次被看见，而这个代价在真实使用里
/// 是「用户重开一次应用」就够了。
fn is_newer(previous: Peer, sequence: u64) -> bool {
    sequence > previous.sequence
}

/// 大厅里当前看到的全部对端。
///
/// # 它是纯逻辑，不碰 socket
///
/// 这个类型只回答一个问题：「我收到了这些公告，现在我认为网段上有谁」。收发字节的
/// 事在 [`crate::lan::lobby`] 里。分开的好处是这条推理可以在一个进程里跑到收敛——
/// 见本模块的 `three_devices_converge` 测试：三台设备各自的视图互相喂对方的公告，
/// 最终必须一致，而这一步不需要任何网络。
#[derive(Debug, Clone, Default)]
pub struct LanView {
    /// 按设备标识索引的对端。
    peers: Vec<Peer>,
}

impl LanView {
    /// 最多记住多少个对端。
    ///
    /// # 这个上限是安全性质，不是性能调优
    ///
    /// 报文里带的是 32 字节的设备标识，而**设备标识是公开信息**——任何一台同网段的
    /// 机器都能凭空造出无数个「新设备」往组播组里发公告，每条只需要 84 字节。没有
    /// 上限的话，一份「不停发公告」的脚本就能让接收方的内存无界增长，而那不是一次
    /// 复杂的攻击，是十几行代码。
    ///
    /// 取 1024：一个真实的局域网里不会有这么多待同步设备（一个家庭或小办公室的设备
    /// 总数是个位数），因此这个上限在正常使用中永远碰不到；而真被碰到时，正确的处置
    /// 是**丢掉最不活跃的那些**，不是拒绝服务。
    pub const MAX_PEERS: usize = 1024;

    /// 一个空视图。
    #[must_use]
    pub const fn new() -> Self {
        Self { peers: Vec::new() }
    }

    /// 收下一条公告，返回它是否改变了什么。
    ///
    /// `now_ms` 由调用方给出——本 crate 不读时钟，理由与核心库相同：一个自己读时钟的
    /// 库无法被测试，也无法让上层决定「现在」是什么（比如上层可能想让整个界面停在
    /// 某个时刻）。
    ///
    /// # 返回 `false` 的三种情况
    ///
    /// 序号不比已知的新（乱序或重复投递）、同一条 `Bye` 收到两次、以及……没有第三种。
    /// **返回 `false` 不代表报文坏了**——报文坏了在 [`Announcement::decode`] 那一步就
    /// 已经返回错误了。把「没改变什么」与「坏了」混在一个返回值里，会让调用方无法
    /// 决定要不要为它记一条日志。
    pub fn observe(&mut self, announcement: Announcement, now_ms: u64) -> bool {
        let device = announcement.device;

        if let Some(previous) = self.peers.iter_mut().find(|peer| peer.device == device) {
            if !is_newer(*previous, announcement.sequence) {
                return false;
            }
            previous.endpoint_key = announcement.endpoint_key;
            previous.port = announcement.port;
            previous.status = match announcement.kind {
                Kind::Hello => PeerStatus::Here,
                Kind::Bye => PeerStatus::Left,
            };
            previous.last_seen_ms = now_ms;
            previous.sequence = announcement.sequence;
            return true;
        }

        // 满了就先腾位置。**丢最不活跃的那个**，而不是拒绝这一条：一条公告代表
        // 「这个网段上有一台设备」，而丢掉刚听到的那台恰好是用户最可能正看着的那台。
        // 见 [`LanView::MAX_PEERS`]。
        if self.peers.len() >= Self::MAX_PEERS {
            self.evict_least_recent();
        }

        self.peers.push(Peer {
            device,
            endpoint_key: announcement.endpoint_key,
            port: announcement.port,
            status: match announcement.kind {
                Kind::Hello => PeerStatus::Here,
                Kind::Bye => PeerStatus::Left,
            },
            last_seen_ms: now_ms,
            sequence: announcement.sequence,
        });
        true
    }

    /// 丢掉一个最不活跃的对端。
    ///
    /// 判据是「最后一次听到的时刻最早」，平局时取设备标识最小的那个——**必须是确定性
    /// 的**：一个依赖内部存储顺序的淘汰策略会让两个视图在同样的输入序列下丢掉不同的
    /// 对端，而「各方的视图收敛到同一份名单」正是大厅要保证的性质。
    fn evict_least_recent(&mut self) {
        let Some(victim) = self
            .peers
            .iter()
            .enumerate()
            .min_by_key(|(_, peer)| (peer.last_seen_ms, peer.device))
            .map(|(index, _)| index)
        else {
            return;
        };
        self.peers.swap_remove(victim);
    }

    /// 当前认为「在这里」的全部对端，按设备标识排序。
    ///
    /// 排序是为了让调用方拿到一个**稳定**的顺序：不排序的话，界面上「刚刚出现的设备」
    /// 会随着内部存储顺序变化而跳动，而那与任何真实事件都无关。
    #[must_use]
    pub fn here(&self) -> Vec<Peer> {
        let mut peers: Vec<Peer> = self
            .peers
            .iter()
            .copied()
            .filter(|peer| peer.status == PeerStatus::Here)
            .collect();
        peers.sort_by_key(|peer| peer.device);
        peers
    }

    /// 全部对端（含已离开的），按设备标识排序。
    #[must_use]
    pub fn all(&self) -> Vec<Peer> {
        let mut peers = self.peers.clone();
        peers.sort_by_key(|peer| peer.device);
        peers
    }

    /// 查一个对端。
    #[must_use]
    pub fn get(&self, device: &DeviceId) -> Option<Peer> {
        self.peers
            .iter()
            .find(|peer| peer.device == *device)
            .copied()
    }

    /// 在多少毫秒没听到之后就不再认为对端「在这里」。
    ///
    /// 3 分钟。取值考虑的是公告周期（[`crate::lan::lobby::ANNOUNCE_INTERVAL_MS`] 是
    /// 30 秒）能容忍多大的抖动：4 个周期都丢了才判定离线，够容忍一次短暂的休眠或
    /// 一次 ARP 风暴。反过来它也不能太长，否则用户关了一台设备之后，另一台上那个
    /// 「可用设备」会一直挂在那里。
    pub const STALE_AFTER_MS: u64 = 180_000;

    /// 按租约把过期的对端标成不再「在这里」。
    ///
    /// # 为什么是「标成」而不是「删掉」
    ///
    /// 删掉会让序号水位一起消失，于是一条**早就发过的**旧公告（比如被攻击者录下来
    /// 重放的）会重新变成「新消息」。留着水位让重放仍然被挡在 [`LanView::observe`]
    /// 的序号比较那一步。真正要释放内存的调用方显式用
    /// [`LanView::forget`]。
    ///
    /// # 它会把序号推高
    ///
    /// 标记过期之后，这个对端的序号被推到 `max(已知) + 1`。理由是**这一层要能被
    /// 重放**：大厅的后台线程先在自己那份视图上做这件事，再把结果交给界面线程那份
    /// 视图，而后者走的是同一个 [`LanView::observe`]。若被标成过期的对端在那边仍然
    /// 是「在这里」，序号与已知的相等就会被当成旧消息丢掉——两边于是不一致。把水位
    /// 推高一格，让这条状态变化能被重新说出来，代价是重放窗口**不会**因此变大：真正
    /// 的旧公告序号远低于新水位，照样被挡。
    ///
    /// 返回被标掉的设备，便于调用方去收拾对应的连接。
    pub fn expire(&mut self, now_ms: u64) -> Vec<DeviceId> {
        let mut expired = Vec::new();
        for peer in &mut self.peers {
            if peer.status == PeerStatus::Here
                && now_ms.saturating_sub(peer.last_seen_ms) > Self::STALE_AFTER_MS
            {
                peer.status = PeerStatus::Left;
                peer.sequence = peer.sequence.saturating_add(1);
                expired.push(peer.device);
            }
        }
        expired
    }

    /// 彻底忘掉一个对端（连序号水位一起）。
    ///
    /// # 它会重新打开重放窗口
    ///
    /// 因此只应当在用户显式动作（「移除这台设备」）时调用，不要拿它当租约过期的
    /// 清理手段——那件事是 [`LanView::expire`] 的职责。
    pub fn forget(&mut self, device: &DeviceId) -> bool {
        let before = self.peers.len();
        self.peers.retain(|peer| peer.device != *device);
        self.peers.len() != before
    }

    /// 当前记住了多少个对端（含已离开的）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// 视图是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一台设备：`seed` 同时决定设备标识与端点公钥，测试里一眼能对上。
    fn device(seed: u8) -> (DeviceId, EndpointKey) {
        (
            DeviceId::from_bytes([seed; 32]),
            EndpointKey::from_bytes([seed.wrapping_add(0x80); 32]),
        )
    }

    /// 造一个端点公钥。
    fn endpoint_key(seed: u8) -> EndpointKey {
        EndpointKey::from_bytes([seed; 32])
    }

    fn hello(seed: u8, sequence: u64) -> Announcement {
        let (device, endpoint_key) = device(seed);
        Announcement {
            kind: Kind::Hello,
            sequence,
            device,
            endpoint_key,
            port: 41_000 + u16::from(seed),
        }
    }

    /// **线格式必须逐字节钉住。**
    ///
    /// 这里刻意**手写**期望的字节，而不是拿 [`Announcement::encode`] 与
    /// [`Announcement::decode`] 互相对照——后者只能证明「编解码自洽」，对「两边一起
    /// 改错」完全盲。这个格式一旦发出去就改不动了，因此第一个字节到最后一个字节都要
    /// 在这里出现过一次。
    #[test]
    fn wire_format_is_pinned() {
        let announcement = Announcement {
            kind: Kind::Hello,
            sequence: 0x0102_0304_0506_0708,
            device: DeviceId::from_bytes([0xAA; 32]),
            endpoint_key: EndpointKey::from_bytes([0xBB; 32]),
            port: 0xCCDD,
        };
        let bytes = announcement.encode();

        assert_eq!(bytes.len(), DATAGRAM_LEN);
        assert_eq!(&bytes[0..8], b"Q2FALAN\0");
        assert_eq!(bytes[8], 1, "版本");
        assert_eq!(bytes[9], 0x01, "Hello");
        assert_eq!(
            &bytes[10..18],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "序号是大端"
        );
        assert_eq!(&bytes[18..50], &[0xAA; 32], "设备标识");
        assert_eq!(&bytes[50..82], &[0xBB; 32], "端点公钥");
        assert_eq!(&bytes[82..84], &[0xCC, 0xDD], "端口是大端");

        assert_eq!(
            Announcement::decode(&bytes).expect("自己编的必须解得开"),
            announcement
        );
    }

    #[test]
    fn every_kind_round_trips() {
        for kind in [Kind::Hello, Kind::Bye] {
            let mut announcement = hello(7, 42);
            announcement.kind = kind;
            let decoded = Announcement::decode(&announcement.encode()).expect("往返");
            assert_eq!(decoded, announcement, "种类 {kind:?} 往返不一致");
        }
    }

    /// 边界的端口与序号必须原样往返。
    #[test]
    fn boundary_values_round_trip() {
        for (sequence, port) in [(0_u64, 1_u16), (u64::MAX, u16::MAX), (1, 0)] {
            let mut announcement = hello(1, sequence);
            announcement.port = port;
            let decoded = Announcement::decode(&announcement.encode()).expect("往返");
            assert_eq!(decoded.sequence, sequence);
            assert_eq!(decoded.port, port);
        }
    }

    /// 别人的报文必须被报成「不是我们的」，而不是「我们的但坏了」。
    #[test]
    fn foreign_datagrams_are_recognized_as_foreign() {
        for datagram in [
            b"".as_slice(),
            b"hello",
            b"GET / HTTP/1.1\r\n",
            b"Q2FALAN",       // 魔数只差一点，但长度不够
            b"q2falan\0",     // 大小写敏感
            b"Q2FASYN\0\x01", // 核心库同步载荷的魔数
        ] {
            let result = Announcement::decode(datagram);
            let is_foreign = matches!(result, Err(Error::NotOurDatagram));
            assert!(is_foreign, "应当报「不是我们的报文」，实际 {result:?}");
        }
    }

    /// 魔数对上之后，其余每一处不合规都要**分开**报。
    ///
    /// 混在一起报的代价是将来加字段时无从判断旧客户端到底怎么处理了它。
    #[test]
    fn our_datagrams_are_diagnosed_precisely() {
        let good = hello(3, 9).encode();

        // 长度不对：多一个字节、少一个字节都要报。
        for length in [DATAGRAM_LEN - 1, DATAGRAM_LEN + 1] {
            let mut bad = good.to_vec();
            bad.resize(length, 0);
            let result = Announcement::decode(&bad);
            let is_length = matches!(result, Err(Error::BadDatagramLength { .. }));
            assert!(is_length, "{length} 字节应当报长度不对，实际 {result:?}");
        }

        // 版本比本机新。
        let mut newer = good;
        newer[8] = VERSION + 1;
        let result = Announcement::decode(&newer);
        let is_version = matches!(
            result,
            Err(Error::UnsupportedDatagramVersion { found, supported })
                if found == VERSION + 1 && supported == VERSION
        );
        assert!(is_version, "应当报版本比本机新，实际 {result:?}");

        // 种类不认识。版本先判，因此这里必须把版本改回来。
        let mut unknown = good;
        unknown[8] = VERSION;
        unknown[9] = 0x7F;
        let result = Announcement::decode(&unknown);
        let is_kind = matches!(result, Err(Error::UnknownDatagramKind { kind: 0x7F }));
        assert!(is_kind, "应当报种类不认识，实际 {result:?}");
    }

    /// 组播组里的噪声不得让解析器 panic，也不得让它接受。
    ///
    /// 这段循环是 fuzz 目标 `lan_datagram` 的廉价版本：它盯的是「任何长度、任何内容
    /// 都不得 panic」，而那条性质在解析器上比在别处更容易破——凡是按偏移切片的地方
    /// 都是候选。
    #[test]
    fn arbitrary_bytes_never_panic() {
        let good = hello(1, 1).encode();
        for length in 0..=(DATAGRAM_LEN + 4) {
            for fill in [0x00_u8, 0xFF, 0x51, 0x0A] {
                let mut bytes = vec![fill; length];
                // 一半的时候给它一个真魔数，好让解析走进更深的路径。
                if length >= 8 && fill == 0x51 {
                    bytes[..8].copy_from_slice(MAGIC);
                } else if length >= 8 {
                    bytes[..8].copy_from_slice(&good[..8]);
                }
                let _ = Announcement::decode(&bytes);
            }
        }
    }

    /// 视图把「谁在这里」算对。
    #[test]
    fn the_view_reports_who_is_here() {
        let mut view = LanView::new();
        assert!(view.is_empty());
        assert!(view.observe(hello(1, 0), 1_000), "第一条公告必须被收下");
        assert_eq!(view.len(), 1);

        assert!(view.observe(hello(2, 0), 1_000));
        assert_eq!(view.here().len(), 2);

        // 序号不增的公告不改变任何东西。
        assert!(
            !view.observe(hello(1, 0), 2_000),
            "同一序号重复到达不该算新消息"
        );
        assert_eq!(
            view.get(&device(1).0).expect("在视图里").last_seen_ms,
            1_000,
            "被忽略的公告不该刷新时间戳"
        );

        // 序号更大的公告刷新。
        assert!(view.observe(hello(1, 1), 2_000));
        assert_eq!(
            view.get(&device(1).0).expect("在视图里").last_seen_ms,
            2_000
        );
    }

    /// `Bye` 之后 `Hello` 必须能把他带回来（设备重启的情形）。
    #[test]
    fn a_peer_can_come_back_after_saying_goodbye() {
        let mut view = LanView::new();
        let (id, _) = device(5);

        view.observe(hello(5, 0), 1_000);
        assert_eq!(view.here().len(), 1);

        let mut bye = hello(5, 1);
        bye.kind = Kind::Bye;
        assert!(view.observe(bye, 2_000));
        assert!(view.here().is_empty(), "说过再见的设备不该还算「在这里」");
        assert_eq!(view.len(), 1, "但他仍在视图里——序号水位要留着");
        assert_eq!(view.get(&id).expect("在视图里").status, PeerStatus::Left);

        // 重启之后序号从头开始。它比水位小，因此**不会**被当成新消息——这正是序号
        // 水位的作用，也是这条测试要钉住的取舍：应用重开一次就够了，而一个「序号变小
        // 就当新消息」的实现会让重放彻底失效。
        assert!(!view.observe(hello(5, 0), 3_000), "序号倒退不算新消息");
        assert!(view.here().is_empty());

        // 序号继续往前走的公告把他带回来。
        assert!(view.observe(hello(5, 2), 4_000));
        assert_eq!(view.here().len(), 1);
        assert_eq!(view.get(&id).expect("在视图里").status, PeerStatus::Here);
    }

    /// 租约：久不吭声的对端不再算「在这里」，但**不被删掉**。
    #[test]
    fn a_silent_peer_expires_but_is_remembered() {
        let mut view = LanView::new();
        view.observe(hello(1, 0), 1_000);
        view.observe(hello(2, 0), 1_000);

        assert!(
            view.expire(1_000 + LanView::STALE_AFTER_MS).is_empty(),
            "刚好到期不算过期"
        );
        let expired = view.expire(1_000 + LanView::STALE_AFTER_MS + 1);
        assert_eq!(expired.len(), 2);
        assert!(view.here().is_empty());
        assert_eq!(view.len(), 2, "水位必须留着，否则旧公告可以被重放");

        // 已经过期的对端不会在下一轮里再被报一遍。
        assert!(
            view.expire(999_999).is_empty(),
            "同一个对端只该被报一次过期"
        );
    }

    /// **「过期」这件事必须能被重放出来。**
    ///
    /// 大厅有两个视图：后台线程那份（真正做推理的）与 `Lobby` 那份（给调用方看的）。
    /// 它们之间只靠事件队列同步，因此「过期」必须能被表达成一次普通的
    /// [`LanView::observe`]——否则两边会不一致，而症状是「设备列表里那台已经关掉的
    /// 机器一直挂着」。
    ///
    /// 这条测试同时钉住了 [`LanView::expire`] 为什么要推高序号：不推高的话，下面
    /// 第二次 `observe` 会被「序号不增就是旧消息」挡掉。
    #[test]
    fn an_expiry_can_be_replayed_into_another_view() {
        let (id, _) = device(1);
        let mut first = LanView::new();
        first.observe(hello(1, 0), 0);

        let later = LanView::STALE_AFTER_MS + 1;
        assert_eq!(first.expire(later), vec![id]);
        let expired = first.get(&id).expect("还在视图里");

        // 第二份视图处于「他还在」的状态，收到这条过期通知之后必须也变成「已离开」。
        let mut second = LanView::new();
        second.observe(hello(1, 0), 0);
        assert_eq!(second.here().len(), 1);

        let replay = Announcement {
            kind: Kind::Bye,
            sequence: expired.sequence,
            device: expired.device,
            endpoint_key: expired.endpoint_key,
            port: expired.port,
        };
        assert!(second.observe(replay, later), "过期通知必须被当成新消息");
        assert!(second.here().is_empty());
        assert_eq!(
            second.get(&id).expect("还在视图里").status,
            PeerStatus::Left
        );
    }

    /// 「离开」与「过期」描述的是同一件事，因此视图对两者的处理必须一致。
    #[test]
    fn saying_goodbye_and_expiring_leave_the_same_state() {
        let (id, _) = device(2);

        let mut said = LanView::new();
        said.observe(hello(2, 0), 0);
        let mut bye = hello(2, 1);
        bye.kind = Kind::Bye;
        said.observe(bye, 500);

        let mut expired = LanView::new();
        expired.observe(hello(2, 0), 0);
        expired.expire(LanView::STALE_AFTER_MS + 1);

        let said = said.get(&id).expect("在视图里");
        let expired = expired.get(&id).expect("在视图里");
        assert_eq!(said.status, expired.status);
        assert_eq!(said.endpoint_key, expired.endpoint_key);
        assert_eq!(said.port, expired.port);
        assert_eq!(said.device, expired.device);
    }

    /// **三台设备的视图必须收敛。**
    ///
    /// 每台设备把自己的公告喂给另外两台（正如组播会做的那样），最终三份视图必须给出
    /// **同一份名单**——也就是本次会话里全部三台设备。这条测试是这条推理能在单机上被
    /// 验证的全部理由：它不需要任何网络，因此也不会在 CI 上变成噪声。
    ///
    /// 注意名单里**包含自己**。视图是「这次同步的参与者名单」，不是「远端设备列表」：
    /// 发起方要决定「人齐了没有」，而那个问题只有把所有人（含自己）都算进来才答得对。
    #[test]
    fn three_devices_converge() {
        let mut views = [LanView::new(), LanView::new(), LanView::new()];
        let hellos = [hello(1, 0), hello(2, 0), hello(3, 0)];

        for (sender, announcement) in hellos.iter().enumerate() {
            for (receiver, view) in views.iter_mut().enumerate() {
                // 自己发的那一条由 `lobby` 层显式丢掉（见
                // `a_device_never_becomes_its_own_peer`），因此这里如实模拟组播的
                // 投递规则。
                if sender == receiver {
                    continue;
                }
                view.observe(*announcement, 10_000);
            }
        }

        // 每台设备自己也要出现在名单里，而那条公告是它自己发出的——因此显式补上。
        for (seed, view) in (1..=3).zip(views.iter_mut()) {
            view.observe(hello(seed, 0), 10_000);
        }

        let expected: Vec<DeviceId> = (1..=3).map(|seed| device(seed).0).collect();
        for (index, view) in views.iter().enumerate() {
            let here: Vec<DeviceId> = view.here().into_iter().map(|peer| peer.device).collect();
            assert_eq!(here, expected, "第 {index} 台设备的视图没有收敛");
        }
    }

    /// 名单里包含自己，且自己那条不会因为「和别人的公告撞上」而出错。
    ///
    /// 这条盯的是 [`LanView`] 的键：它是**设备标识**而不是「对端 vs 本机」的二元状态。
    /// 一个用「除我之外」过滤视图的实现会让上面那条收敛测试红，而这条测试把「为什么
    /// 不能那样过滤」写成了可执行的句子。
    #[test]
    fn the_view_includes_its_own_device() {
        let mut view = LanView::new();
        let (me, _) = device(9);
        assert!(view.observe(hello(9, 0), 1_000));
        assert_eq!(view.here().len(), 1);
        assert_eq!(view.here()[0].device, me);
    }

    /// **视图必须有界。**
    ///
    /// 设备标识是公开信息：同网段的任何一台机器都能凭空造出无数个「新设备」发公告，
    /// 每条 84 字节。没有上限的话，一份十几行的脚本就能让接收方的内存无界增长。
    ///
    /// 这条测试把 [`LanView::MAX_PEERS`] 真的撑满一次——不是「算一下会不会超」，
    /// 而是真的喂进去那么多条。
    #[test]
    fn the_view_is_bounded_under_a_flood_of_new_devices() {
        let mut view = LanView::new();
        let flood = LanView::MAX_PEERS + 500;

        for index in 0..flood {
            // 每条公告都自称一台**从没见过**的设备。
            let mut seed = [0_u8; 32];
            seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let announcement = Announcement {
                kind: Kind::Hello,
                sequence: 0,
                device: DeviceId::from_bytes(seed),
                endpoint_key: endpoint_key(0),
                port: 1,
            };
            view.observe(announcement, index as u64);
        }

        assert_eq!(
            view.len(),
            LanView::MAX_PEERS,
            "视图必须停在 MAX_PEERS 个对端，而不是跟着输入一起长"
        );
    }

    /// 淘汰必须是**确定性的**，且丢掉的是最不活跃的那些。
    ///
    /// 「各方视图收敛到同一份名单」是大厅要保证的性质，而一个依赖内部存储顺序的淘汰
    /// 策略会让两个收到同样公告序列的视图丢掉不同的对端——那种不一致极难从现象回溯。
    #[test]
    fn eviction_drops_the_least_recently_seen() {
        let mut view = LanView::new();

        // 先把水位填满，最旧的那条在 t=0，最新的在 t=N。
        for index in 0..LanView::MAX_PEERS {
            view.observe(announcement_for(device_at(index)), index as u64);
        }
        // 此刻 `device_at(0)` 是最不活跃的（它在 t=0 被听到）。
        assert!(view.get(&device_at(0)).is_some());

        // 再来一台新设备，它必须顶掉 `device_at(0)` 而不是别人。
        let newcomer = DeviceId::from_bytes([0xFF; 32]);
        view.observe(
            Announcement {
                kind: Kind::Hello,
                sequence: 0,
                device: newcomer,
                endpoint_key: endpoint_key(1),
                port: 1,
            },
            LanView::MAX_PEERS as u64 + 1,
        );

        assert_eq!(view.len(), LanView::MAX_PEERS);
        assert!(view.get(&newcomer).is_some(), "新来的必须在名单里");
        assert!(view.get(&device_at(0)).is_none(), "最不活跃的应当被顶掉");
        assert!(view.get(&device_at(1)).is_some(), "次旧的还在");
    }

    /// 淘汰之后**同一个对端仍然能回来**（它的序号水位被一起丢了）。
    ///
    /// 这是 [`LanView::forget`] 那条代价的另一面：被淘汰的对端与「显式忘掉」在状态上
    /// 没有区别。把它写下来，是为了让「淘汰为什么只能在满了的时候发生」有一个具体的
    /// 理由——它确实会重新打开那个对端的重放窗口。
    #[test]
    fn an_evicted_peer_restarts_from_a_clean_watermark() {
        let mut view = LanView::new();
        for index in 0..LanView::MAX_PEERS {
            view.observe(announcement_for(device_at(index)), index as u64);
        }
        let victim = device_at(0);

        // 被顶掉之前，序号倒退会被挡住。
        assert!(
            !view.observe(announcement_for(victim), 0),
            "水位还在时序号倒退被挡"
        );

        // 顶掉之后，同一条公告又能进来了。
        view.observe(
            Announcement {
                kind: Kind::Hello,
                sequence: 0,
                device: DeviceId::from_bytes([0xEE; 32]),
                endpoint_key: endpoint_key(2),
                port: 1,
            },
            LanView::MAX_PEERS as u64 + 1,
        );
        assert!(view.get(&victim).is_none(), "牺牲者应当已经被顶掉");
        assert!(
            view.observe(announcement_for(victim), 0),
            "水位没了，旧序号又能进来"
        );
    }

    /// 造一条来自某台设备的公告（序号 0）。
    fn announcement_for(device: DeviceId) -> Announcement {
        Announcement {
            kind: Kind::Hello,
            sequence: 0,
            device,
            endpoint_key: endpoint_key(0),
            port: 1,
        }
    }

    /// 造一台「第 `index` 号」设备。用它把视图填满。
    fn device_at(index: usize) -> DeviceId {
        let mut seed = [0_u8; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        DeviceId::from_bytes(seed)
    }

    /// 忘掉一个对端会连水位一起清掉，因此旧公告又能进来了。
    ///
    /// **这条是被刻意钉住的：它是 `forget` 的代价，不是缺陷。** 把它写下来是为了让
    /// 后人看到「为什么过期用 `expire` 而不是 `forget`」时有一个具体的理由。
    #[test]
    fn forgetting_a_peer_reopens_the_replay_window() {
        let mut view = LanView::new();
        let (id, _) = device(4);
        view.observe(hello(4, 100), 1_000);
        assert!(!view.observe(hello(4, 0), 2_000), "序号倒退被挡");

        assert!(view.forget(&id));
        assert!(view.is_empty());
        assert!(view.observe(hello(4, 0), 3_000), "水位没了，旧公告又能进来");
    }

    /// 调试输出只打印前 8 字节，不刷屏。
    #[test]
    fn debug_output_is_short() {
        let key = EndpointKey::from_bytes([0x80; 32]);
        assert_eq!(format!("{key:?}"), "EndpointKey(8080808080808080)");
        // 后面的字节一个都不打印——一条日志行里出现两个 32 字节十六进制串只会让人
        // 读不下去，而排查「这两台设备对上了没有」只需要一个短前缀。
        let text = format!("{:?}", EndpointKey::from_bytes([1; 32]));
        assert_eq!(text.len(), "EndpointKey(".len() + 16 + 1);
    }
}
