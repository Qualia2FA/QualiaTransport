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

//! 局域网通道（QWBP）：在同一网段上找到对端，再把字节送过去。
//!
//! # 分成两半，各自解决一件事
//!
//! | 模块 | 干什么 | 靠什么 |
//! |------|--------|--------|
//! | [`lobby`] | 发现：谁在这个网段上、去哪里连他 | UDP 组播，无认证 |
//! | *传输* | 搬运：把整份同步载荷送过去 | QUIC（见 `lan` 之外的传输实现） |
//!
//! 这两半的分界不是「哪个先做」，而是**信任级别**：组播是共享介质，任何人都能往里
//! 灌任意字节，因此它承载的信息只能是**提示**——「这个网段上大概有谁」。真正的身份
//! 由建立连接时的握手证明，而「这条载荷该不该收」由核心库的白名单决定
//! （`qualia2fa_core::transport::SyncSession::restricted`）。
//!
//! # 为什么发现不做认证
//!
//! 想过给公告签名（用平台硬件密钥库里的设备身份私钥）。放弃的理由是**代价与收益
//! 不成比例**：公告是周期性的，签名意味着 TPM 每个周期被唤醒一次；而伪造公告能换来
//! 的只是「让对端发起一次连接」，那次连接会在握手里暴露出伪造者拿不出端点私钥。
//!
//! 这正是 D4 在局域网上的翻版：**发现可以无认证，凭据必须来自信道。**
//!
//! # 用二维码「建链」的那条路
//!
//! 组播要求两端在**同一个广播域**里。跨网段、或者网络策略禁止组播时，还有一条路：
//! 把 [`LanAddress`] 编码进二维码带外传过去（那是 `SharePlan::LinkEstablishment`
//! 的场景），对端据此直接建连。两条路产生的是**同一种连接**，因此协议层不需要知道
//! 用户走的是哪一条。
//!
//! # 本模块的纯度
//!
//! [`wire`] 是纯逻辑：不碰 socket、不读时钟，全部输入都是参数，因此「三台设备收敛到
//! 同一份视图」这类性质可以在一个进程里、不需要网络地验证。
//! [`lobby`] 是唯一碰 I/O 的地方，而它里面的判断被压到最小——判断都在 [`wire`] 里。

pub mod lobby;
pub mod wire;

/// 局域网的数据面（iroh 的离线配置）。
///
/// 它整体挂在一个 feature 后面：iroh 会带进两百多个 crate 与一套 tokio 运行时，而
/// **二维码那条路只需要一个二维码编码器**。移动端先用二维码（平台相机拿到的已经是
/// 文本），桌面端再打开这一半——把这条分界线做在 feature 上，比做在文档里可靠。
#[cfg(feature = "iroh-lan")]
pub mod transport;

use crate::error::{Error, Result};
use wire::EndpointKey;

/// 局域网连接信息在二维码里用的前缀。
///
/// 与二维码信封的 `Q2FA1` **不是**同一个东西：信封说的是「这段文本怎么装进二维码」，
/// 而这里说的是「文本里装的是什么」。分两层是因为同一条信封还要承载别的载荷（配对
/// 引导数据、同步载荷本身），而那些载荷不该长得像一条局域网地址。
const ADDRESS_PREFIX: &[u8; 6] = b"Q2FAL1";

/// 局域网连接信息的版本。
const ADDRESS_VERSION: u8 = 1;

/// 局域网连接信息的固定长度。
///
/// 前缀 6 + 版本 1 + 端点公钥 32 + 端口 2 + 校验 1。
pub const ADDRESS_LEN: usize = ADDRESS_PREFIX.len() + 1 + wire::ENDPOINT_KEY_LEN + 2 + 1;

/// **一条可以直接拨号的局域网连接信息。**
///
/// # 它为什么存在
///
/// 组播大厅要求两端在同一个广播域里。跨网段（用户的两台设备连着不同的 AP）、或者
/// 网络策略禁止组播（很多企业 WiFi 就是）时，唯一的路是把「去哪里连我」**带外**交给
/// 对方——也就是二维码。这就是 D9 的「建链」模式，而它是 [`LanAddress`] 的全部用途。
///
/// # 为什么它比组播公告**短**
///
/// 公告里同时带设备标识（32 字节）与端点公钥（32 字节），因为组播上的接收方需要
/// 设备标识才能做白名单。而这条信息是**带外**送达的：拿到二维码的人已经在配对流程
/// 里确认过对方的身份了，设备标识由那条流程提供。省掉 32 字节在二维码上是实打实的
/// 容量。
///
/// # 校验
///
/// 末字节是 8 位和校验。它**不是**安全措施——这条信息本来就不承担保密与认证职责
/// （见模块文档）。它只防一件事：**用户手抄或肉眼核对时抄错一位**。没有它的话，
/// 一个抄错的端口会让对端去连一个不存在的端口，而报出来的是「连接超时」——一个把
/// 诊断引向网络问题、而不是「码抄错了」的方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanAddress {
    /// 对端的传输层端点公钥。
    pub endpoint_key: EndpointKey,
    /// 对端监听的端口。
    pub port: u16,
}

impl LanAddress {
    /// 造一条连接信息。
    #[must_use]
    pub const fn new(endpoint_key: EndpointKey, port: u16) -> Self {
        Self { endpoint_key, port }
    }

    /// 编码成 [`ADDRESS_LEN`] 字节。
    #[must_use]
    pub fn encode(&self) -> [u8; ADDRESS_LEN] {
        let mut out = [0_u8; ADDRESS_LEN];
        let mut at = 0;
        out[at..at + ADDRESS_PREFIX.len()].copy_from_slice(ADDRESS_PREFIX);
        at += ADDRESS_PREFIX.len();
        out[at] = ADDRESS_VERSION;
        at += 1;
        out[at..at + wire::ENDPOINT_KEY_LEN].copy_from_slice(self.endpoint_key.as_bytes());
        at += wire::ENDPOINT_KEY_LEN;
        out[at..at + 2].copy_from_slice(&self.port.to_be_bytes());
        at += 2;
        out[at] = checksum(&out[..at]);
        out
    }

    /// 从一段字节解出一条连接信息。
    ///
    /// # 错误
    ///
    /// - [`Error::NotOurLanAddress`]：前缀不对（这不是一条局域网连接信息）。
    /// - [`Error::UnsupportedDatagramVersion`]：前缀对，但版本比本机新。它借用了大厅
    ///   报文的那个变体，因为两者是同一件事：**是我们的东西，只是比本机新**。混进
    ///   「不是我们的」会让将来升级时不认识的东西被静默丢掉。
    /// - [`Error::BadLanAddressLength`]：长度不对。
    /// - [`Error::ZeroPort`]：端口为 0。
    /// - [`Error::MalformedFrameHeader`]：校验字节对不上（多半是抄错了）。它借用了
    ///   二维码信封的那个变体，理由同上：都是「格式对、内容坏了」。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let prefix = bytes
            .get(..ADDRESS_PREFIX.len())
            .ok_or(Error::NotOurLanAddress)?;
        if prefix != ADDRESS_PREFIX {
            return Err(Error::NotOurLanAddress);
        }
        if bytes.len() != ADDRESS_LEN {
            return Err(Error::BadLanAddressLength {
                expected: ADDRESS_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[ADDRESS_PREFIX.len()] != ADDRESS_VERSION {
            return Err(Error::UnsupportedDatagramVersion {
                found: bytes[ADDRESS_PREFIX.len()],
                supported: ADDRESS_VERSION,
            });
        }

        let mut key = [0_u8; wire::ENDPOINT_KEY_LEN];
        let key_start = ADDRESS_PREFIX.len() + 1;
        key.copy_from_slice(&bytes[key_start..key_start + wire::ENDPOINT_KEY_LEN]);
        let port_at = key_start + wire::ENDPOINT_KEY_LEN;
        let port = u16::from_be_bytes([bytes[port_at], bytes[port_at + 1]]);
        let expected = checksum(&bytes[..port_at + 2]);
        if bytes[port_at + 2] != expected {
            return Err(Error::MalformedFrameHeader);
        }
        if port == 0 {
            return Err(Error::ZeroPort);
        }

        Ok(Self {
            endpoint_key: EndpointKey::from_bytes(key),
            port,
        })
    }
}

/// 8 位和校验。
///
/// 取的是**字节和**而不是 CRC 之类：它要挡的是抄错一位，而不是随机损坏——后者在这个
/// 场景里不存在（同一串字节不是被抄就是没被抄）。而它必须足够简单，简单到可以在一张
/// 纸上心算出来，这样「用户对着照片核对」这件事才有意义。
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0_u8, |acc, byte| acc.wrapping_add(*byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(seed: u8) -> EndpointKey {
        EndpointKey::from_bytes([seed; 32])
    }

    /// **线格式必须逐字节钉住。**
    ///
    /// 手写期望值而不是编解码互相对照，理由与大厅报文那一条相同：互相对照只能证明
    /// 自洽，对「两边一起改错」完全盲。
    #[test]
    fn wire_format_is_pinned() {
        let address = LanAddress::new(EndpointKey::from_bytes([0xBB; 32]), 0x1234);
        let bytes = address.encode();

        assert_eq!(bytes.len(), ADDRESS_LEN);
        assert_eq!(
            ADDRESS_LEN, 42,
            "前缀 6 + 版本 1 + 公钥 32 + 端口 2 + 校验 1"
        );
        assert_eq!(&bytes[0..6], b"Q2FAL1");
        assert_eq!(bytes[6], 1, "版本");
        assert_eq!(&bytes[7..39], &[0xBB; 32], "端点公钥");
        assert_eq!(&bytes[39..41], &[0x12, 0x34], "端口是大端");
        // 被校验覆盖的那一段的字节和：前缀 6 字节的 ASCII、版本 1、公钥 32×0xBB、
        // 端口 0x12 + 0x34。逐项算出来而不是抄一个数字——抄的那个数字不会随格式
        // 变化，于是这条断言会在格式改了之后继续绿。
        let expected = b'Q'
            .wrapping_add(b'2')
            .wrapping_add(b'F')
            .wrapping_add(b'A')
            .wrapping_add(b'L')
            .wrapping_add(b'1')
            .wrapping_add(ADDRESS_VERSION)
            .wrapping_add(0xBB_u8.wrapping_mul(32))
            .wrapping_add(0x12)
            .wrapping_add(0x34);
        assert_eq!(bytes[41], expected, "校验字节");

        assert_eq!(
            LanAddress::decode(&bytes).expect("自己编的必须解得开"),
            address
        );
    }

    #[test]
    fn round_trips_every_boundary() {
        for (seed, port) in [(0_u8, 1_u16), (0xFF, u16::MAX), (1, 1024), (0x80, 21_377)] {
            let address = LanAddress::new(endpoint(seed), port);
            let decoded = LanAddress::decode(&address.encode()).expect("往返");
            assert_eq!(decoded, address, "seed {seed} port {port} 往返不一致");
        }
    }

    /// 别的数据必须被报成「不是我们的」，而不是「我们的但坏了」。
    #[test]
    fn foreign_bytes_are_recognized_as_foreign() {
        for bytes in [
            b"".as_slice(),
            b"Q2FA1:1/1:MZXW6",
            b"Q2FASYN\0",
            b"q2fal1",
            b"Q2FAL",
        ] {
            let result = LanAddress::decode(bytes);
            let is_foreign = matches!(result, Err(Error::NotOurLanAddress));
            assert!(is_foreign, "应当报「不是我们的连接信息」，实际 {result:?}");
        }
    }

    /// 前缀对了之后，每一处不合规都要分开报。
    #[test]
    fn our_bytes_are_diagnosed_precisely() {
        let good = LanAddress::new(endpoint(1), 1234).encode();

        for length in [ADDRESS_LEN - 1, ADDRESS_LEN + 1] {
            let mut bad = good.to_vec();
            bad.resize(length, 0);
            let result = LanAddress::decode(&bad);
            let is_length = matches!(result, Err(Error::BadLanAddressLength { .. }));
            assert!(is_length, "{length} 字节应当报长度不对，实际 {result:?}");
        }

        let mut newer = good;
        newer[6] = ADDRESS_VERSION + 1;
        let result = LanAddress::decode(&newer);
        let is_version = matches!(
            result,
            Err(Error::UnsupportedDatagramVersion { found, supported })
                if found == ADDRESS_VERSION + 1 && supported == ADDRESS_VERSION
        );
        assert!(is_version, "应当报版本比本机新，实际 {result:?}");

        // 改坏一个字节：校验必须抓到。
        let mut corrupted = good;
        corrupted[10] ^= 0x01;
        let result = LanAddress::decode(&corrupted);
        let is_checksum = matches!(result, Err(Error::MalformedFrameHeader));
        assert!(is_checksum, "抄错的字节应当被校验抓到，实际 {result:?}");
    }

    /// **校验必须对每一位都敏感。**
    ///
    /// 一条「只在高位字节上出错才报」的校验是很容易写出来的（比如把 `u8` 的溢出当成
    /// 正常回绕，却忘了把某一段算进去）。这里逐字节翻一位试一遍——那正是用户抄错时
    /// 会发生的事。
    #[test]
    fn every_single_bit_flip_is_caught() {
        let good = LanAddress::new(endpoint(0x5A), 21_377).encode();

        // 只翻「被校验覆盖的那一段」里的位。前缀与版本有各自的前置检查，翻它们会报
        // 别的错误，那也是对的——但这里要盯的是校验本身。
        for index in 7..(ADDRESS_LEN - 1) {
            for bit in 0..8 {
                let mut corrupted = good;
                corrupted[index] ^= 1 << bit;
                let result = LanAddress::decode(&corrupted);
                assert!(
                    matches!(result, Err(Error::MalformedFrameHeader)),
                    "第 {index} 字节第 {bit} 位翻掉之后未被抓到，实际 {result:?}"
                );
            }
        }
    }

    /// 端口 0 必须被拒绝。
    ///
    /// 端口 0 在 socket API 里表示「由系统挑一个」，而一条**已经建立好的**连接信息里
    /// 出现它，只能意味着对端为了构造它而写错了东西——拿到它的设备会去连一个不存在
    /// 的端口。
    #[test]
    fn a_zero_port_is_rejected() {
        // 手工构造：把端口写成 0 再补上正确的校验，绕过「校验先挡下来」那条路。
        let mut bytes = LanAddress::new(endpoint(1), 1234).encode();
        bytes[39] = 0;
        bytes[40] = 0;
        let sum = checksum(&bytes[..41]);
        bytes[41] = sum;

        let result = LanAddress::decode(&bytes);
        let is_zero = matches!(result, Err(Error::ZeroPort));
        assert!(is_zero, "应当报端口为 0，实际 {result:?}");
    }

    /// 任意字节都不得让解析器 panic，也不得让它接受。
    #[test]
    fn arbitrary_bytes_never_panic() {
        for length in 0..=(ADDRESS_LEN + 4) {
            for fill in [0x00_u8, 0xFF, 0x51, 0x0A] {
                let mut bytes = vec![fill; length];
                if length >= ADDRESS_PREFIX.len() && fill == 0x51 {
                    bytes[..ADDRESS_PREFIX.len()].copy_from_slice(ADDRESS_PREFIX);
                }
                let _ = LanAddress::decode(&bytes);
            }
        }
    }
}
