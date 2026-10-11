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

//! 本 crate 的错误类型。
//!
//! # 错误信息里只允许出现元数据
//!
//! 尺寸、版本号、帧号、纠错级别可以进错误信息；**载荷内容与扫到的原始文本不可以**。
//! 错误会被写进日志，而日志会被上报、被截图、被贴进 issue——本 crate 处理的虽然多
//! 半是密文，但配对阶段的二维码载荷里就有临时公钥与随机数，它们出现在日志里没有
//! 任何好处。

/// 本 crate 的结果类型。
pub type Result<T> = core::result::Result<T, Error>;

/// 本 crate 的错误。
///
/// 标了 `#[non_exhaustive]`：新增变体不算破坏性变更，而调用方必须留一个兜底分支
/// ——那正是「新增失败模式时编译器的沉默」这一风险的唯一补偿。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// 载荷装不下这条通道。
    ///
    /// `needed` 与 `limit` **都以载荷字节为单位**（不是信封文本的字符数），因为调用方
    /// 拿到的载荷就是若干字节，而「差多少」这个数字要能直接显示给用户。
    #[error("载荷装不下：需要 {needed} 字节，这条通道最多 {limit} 字节")]
    PayloadTooLarge {
        /// 实际需要装下的字节数。
        needed: usize,
        /// 这条通道能装下的最大字节数。
        limit: usize,
    },

    /// 这段文本不是本应用的二维码。
    ///
    /// 与「是本应用的码但坏了」分开，是因为两者对用户的意义完全不同：前者多半是
    /// 用户扫错了码（扫到了别人的二维码），后者才是要重扫或换通道。
    #[error("这不是 Qualia2FA 的二维码")]
    NotOurQrText,

    /// 帧头不合法（格式不对、有前导零、帧号超出帧数）。
    #[error("二维码文本的帧头不合法")]
    MalformedFrameHeader,

    /// 这张码是多帧的（动态二维码），而当前只实现了单帧。
    ///
    /// 单独一个变体是刻意的：多帧是**计划中的格式**，不是坏输入。把它混进
    /// [`Error::MalformedFrameHeader`] 会让将来实现多帧时无从判断「这段文本到底
    /// 是不是我们写的」。
    #[error("这张码有 {count} 帧，当前只支持单帧")]
    MultiFrameUnsupported {
        /// 文本自称的帧数。
        count: u32,
    },

    /// Base32 载荷不合法（非法字符、非法长度，或非规范的尾比特）。
    #[error("二维码文本里的 Base32 载荷不合法")]
    MalformedBase32,

    /// 纠错级别不是 `L`/`M`/`Q`/`H`。
    #[error("纠错级别 {letter:?} 不是 L/M/Q/H")]
    UnknownEcLevel {
        /// 实际拿到的那个字符。
        letter: char,
    },

    /// 二维码版本号不在 1–40 之内。
    #[error("二维码版本 {version} 不在 1–40 之内")]
    VersionOutOfRange {
        /// 实际拿到的版本号。
        version: u8,
    },

    /// 渲染参数不合法。
    #[error("渲染参数不合法：缩放 {scale} 倍、静区 {quiet_zone} 模块")]
    BadRenderGeometry {
        /// 每个模块放大成多少个像素。
        scale: u16,
        /// 四周留出的静区宽度（模块数）。
        quiet_zone: u16,
    },

    /// 图像尺寸与像素数不匹配，或尺寸超出上限。
    #[error("图像尺寸不合法：{width}×{height}，像素 {pixels} 个")]
    BadImageGeometry {
        /// 声称的宽度（像素）。
        width: u32,
        /// 声称的高度（像素）。
        height: u32,
        /// 实际给出的像素个数。
        pixels: usize,
    },

    /// 图像里没有可读的二维码。
    ///
    /// 与 [`Error::QrDecode`] 分开：这一条的含义是「连定位都没成功」，而不是
    /// 「找到了但读不出来」。前者多半是图片里根本没有码（或太小、太糊）。
    #[error("图像里没有找到二维码")]
    NoQrFound,

    /// 扫到的二维码不是文本（因此不可能是本应用的码）。
    #[error("扫到的二维码不是文本")]
    QrNotText,

    /// 图像解码失败。
    ///
    /// 只在开启 `scan-image` feature 时存在——那是这条错误唯一的来源。
    #[cfg(feature = "scan-image")]
    #[error("二维码图像解码失败：{0}")]
    QrDecode(#[from] rqrr::DeQRError),

    /// 这串文本不是本应用的局域网连接信息。
    ///
    /// 与 [`Error::NotOurQrText`] 分开：那一条说的是「扫到的东西不是二维码信封」，
    /// 这一条说的是「信封解开了，但里面装的是别的东西」。把两者合并会让「扫到了
    /// 一张别人的同步码」与「扫到了一张配对码」无法区分，而它们的处置完全不同。
    #[error("这不是 Qualia2FA 的局域网连接信息")]
    NotOurLanAddress,

    /// 局域网连接信息的长度不对。
    ///
    /// 这个结构是**定长**的，因此长度不对就是坏输入，不需要再往下猜。
    #[error("局域网连接信息长度不对：期望 {expected} 字节，实际 {actual} 字节")]
    BadLanAddressLength {
        /// 定长结构的字节数。
        expected: usize,
        /// 实际拿到的字节数。
        actual: usize,
    },

    /// 局域网连接信息里的端口号是 0。
    ///
    /// 端口 0 在协议里表示「由系统挑一个」，因此**不能**出现在一条已经建立好的
    /// 连接信息里：拿到它的对端只能去连一个不存在的端口。
    #[error("局域网连接信息里的端口为 0")]
    ZeroPort,

    /// 收到的 UDP 数据报不是本协议的大厅报文。
    ///
    /// 局域网组播组是**共享**的：同一网段上可能有别人的程序、也可能有人往这个组里
    /// 灌任意字节。魔数不对就是「不是我们的报文」，丢掉了事，不该报成解析失败。
    #[error("这不是 Qualia2FA 的大厅报文")]
    NotOurDatagram,

    /// 大厅报文的承载种类不认识。
    ///
    /// 与 [`Error::NotOurDatagram`] 分开：魔数已经对上了，因此这确实是我们的报文，
    /// 只是**版本比本机新**。混进「不是我们的报文」会让将来加一种报文时，旧版本
    /// 客户端把新客户端的公告当成噪声静默丢掉，而那是很难查的一类故障。
    #[error("不认识的大厅报文种类：{kind}")]
    UnknownDatagramKind {
        /// 实际拿到的种类字节。
        kind: u8,
    },

    /// 大厅报文的格式版本比本机支持的新。
    ///
    /// 单独一个变体，理由与 [`Error::UnknownDatagramKind`] 相同：必须能与「这不是
    /// 我们的报文」区分开。
    #[error("大厅报文版本 {found} 比本机支持的 {supported} 新")]
    UnsupportedDatagramVersion {
        /// 报文自称的版本。
        found: u8,
        /// 本机支持的版本。
        supported: u8,
    },

    /// 大厅报文长度不对。
    #[error("大厅报文长度不对：期望 {expected} 字节，实际 {actual} 字节")]
    BadDatagramLength {
        /// 该种类的报文应有的字节数。
        expected: usize,
        /// 实际拿到的字节数。
        actual: usize,
    },

    /// 局域网上没有找到任何对端。
    ///
    /// 这不是错误状态，而是「还没等到」——调用方据此决定要不要继续等。它与
    /// 「通道坏了」分开报，否则界面会把「同一网段上暂时没有别的设备」显示成一个
    /// 故障。
    #[error("局域网上还没有发现任何对端")]
    NoLanPeersFound,

    /// 局域网 socket 操作失败。
    ///
    /// 与其它变体分开：这一条是**环境**问题（没有网卡、端口被占、组播被防火墙拦），
    /// 而不是输入问题。混在一起会让「网络不可用」显示成「报文坏了」。
    #[error("局域网 socket 操作失败：{operation}")]
    LanSocket {
        /// 哪一个操作失败了（`bind` / `join_multicast` / `send_to` / `recv_from` …）。
        operation: &'static str,
    },

    /// 局域网传输通道收到了发往别处的消息。
    ///
    /// 这个变体存在的唯一理由是**契约**：`Recipient::One` 不得退化成广播。一条
    /// 定向消息若在本机查不到那个对端的连接，正确的处置是报错，而**不是**退而求其次
    /// 发给所有人——那会让「只给 B 的载荷」出现在 C 手里，而用户看不到任何异常。
    #[error("这条定向消息没有可用的连接")]
    NoConnectionToPeer,

    /// 局域网传输层（iroh/QUIC）操作失败。
    ///
    /// 与 [`Error::LanSocket`] 分开：那一条是大厅的 UDP 收发，这一条是数据面的
    /// QUIC 连接。混在一起会让「组播被防火墙拦了」与「QUIC 建连超时」显示成同一个
    /// 故障，而它们的处置完全不同。
    #[error("局域网传输失败：{operation}")]
    LanTransport {
        /// 哪一个操作失败了（`bind` / `connect` / `write` …）。
        operation: &'static str,
    },

    /// 传输入口暂时没有消息。
    ///
    /// # 它不是错误
    ///
    /// 「通道里现在没有东西」与「通道坏了」必须分开：前者调用方应当继续等（或者去
    /// 干别的），后者应当报给用户。核心库把这个区分做成了 [`Error`] 的一个变体，
    /// 而本 crate 不能引用核心库的类型，因此在**这里**再定义一次——语义与那边的
    /// `SyncNoSessionFound` 逐字对应，接起来的那层转发只做一次 `match` 映射，不含
    /// 任何判断。
    ///
    /// 一条把这两种情况混成一个 `Option` 的接口，是让调用方写出
    /// `let _ = receive(...)` 的最短路径，而那一行会让重放防护静默失效。
    #[error("传输通道里暂时没有消息")]
    TransportEmpty,
}
