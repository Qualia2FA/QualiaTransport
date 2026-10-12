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

//! Qualia2FA 的**传输通道**。
//!
//! 本 crate 只做一件事：把一段字节送出去、再把一段字节收回来。协议本身——谁的载荷
//! 先到、冲突怎么报、重放怎么挡——住在 `qualia2fa-core` 里，本 crate 对它一无所知。
//! 两者之间的接口是核心库的 `Transport` trait，而**依赖方向是「本 crate ← 核心库」**：
//! 任何需要「把字节放进二维码」或「在局域网里找到对端」的项目都能直接用本 crate，
//! 不需要接受 Qualia2FA 的保险库格式或账号模型。
//!
//! # 现在有什么
//!
//! | 模块 | 内容 |
//! |------|------|
//! | [`qr`] | 二维码的容量模型、编码、渲染与（可选）图像解码 |
//! | [`envelope`] | 二进制载荷 ↔ 二维码可承载文本 |
//! | [`frame`] | 动态二维码：一份装不下的载荷拆成多张码，扫描方逐张拼 |
//! | [`image`] | 渲染与扫描之间传递像素的形式 |
//! | [`lan`] | 局域网：组播大厅（发现）、连接信息与（可选）QUIC 数据面 |
//!
//! # 为什么二维码要先变成文本
//!
//! 二维码的「字节模式」确实能原样携带任意字节，但那样一来**只有本 crate 自己解得出
//! 来**：平台相机（Android ML Kit、iOS AVFoundation）交回的是字符串，剪贴板里也只能
//! 放文本，人眼抄下来的更只能是文本。于是本 crate 统一把载荷放进一层文本信封，再用
//! 二维码的**字母数字模式**编码——代价只有约 10% 的容量，换来的是「任何扫码器读出来
//! 的都是同一串文本」。详见 [`envelope`] 的模块文档。
//!
//! 那张码装不下整份载荷时，同样的信封再承载**多张码**：帧号与帧数从第一版起就写在
//! 文本里（`Q2FA1:2/3:`），因此多帧不需要新的线格式。拆与拼在 [`frame`]，而「拆得开
//! 就必须画得出」那一层在 [`qr::QrProfile::encode_payload_frames`]。
//!
//! # 二维码与局域网的分工
//!
//! 两条通道**不互相替代**：
//!
//! - 二维码带宽极小、一次性、必须两端都在场，但它**不需要任何网络设施**，也不需要
//!   权限（Android 17 的 `ACCESS_LOCAL_NETWORK`、iOS 的组播 entitlement 都与它无关）。
//! - 局域网带宽充裕、可反复用，但它要求两端在同一个广播域里，而且组播在很多企业
//!   WiFi 上是被禁的。
//!
//! 因此它们的组合是：**发现走哪条路由现场决定，载荷本身走带宽够的那条**。核心库的
//! `SharePlan` 做的就是那个决定，而本 crate 两条路都提供。
//!
//! # 还没有什么
//!
//! 各平台的局域网权限流程（Android 17 的 `ACCESS_LOCAL_NETWORK`、iOS 的
//! `NSLocalNetworkUsageDescription` 与组播 entitlement）属于端侧接入，本 crate 不做。
//! 局域网的「不联网」目前只到「不构建 relay、不注册 DNS/pkarr、关掉 HTTPS 探测」这一
//! 层，**抓包实证尚未完成**，因此不要据此做对外声明（见 `README` 的 `iroh-lan` 一节）。
//!
//! # 纯度约定
//!
//! [`qr`]、[`envelope`]、[`frame`]、[`image`] 与 [`lan::wire`] 是纯逻辑：不碰文件系统、
//! 网络、时钟与环境变量，全部输入都是参数。因此 `#![forbid(unsafe_code)]` 成立，且任何
//! 输入都不得导致 panic——唯一允许的失败方式是返回 [`Error`]。
//!
//! [`lan::lobby`] 是**唯一**碰 I/O 的模块（UDP socket 与一个后台线程），而它里面的
//! 判断被压到最小：所有推理都在 [`lan::wire`] 里，于是「三台设备收敛到同一份视图」
//! 这类性质可以在一个进程里、不需要网络地验证。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod envelope;
pub mod error;
pub mod frame;
pub mod image;
pub mod lan;
pub mod qr;

/// RFC 4648 §6 的 Base32。
///
/// 刻意不依赖现成的 crate：本 crate 的编解码层因此保持**零依赖**，且这份实现的语义
/// 与核心库的 `base32` 显式对齐（大小写不敏感、容忍填充、拒绝非规范尾比特），
/// 免得同一份 RFC 在两个仓库里长出两种行为。
mod base32;

pub use error::{Error, Result};
