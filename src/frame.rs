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

//! **动态二维码**：一份装不下的载荷拆成多张码，扫描方逐张扫、逐张拼。
//!
//! # 它解决的是什么
//!
//! 二维码的容量上限是硬的（[`crate::qr::QrProfile`] 算出来的那个数字），而一份同步
//! 载荷可能比它大。两条出路：改用局域网（带宽充裕，但要两端在同一个广播域），或者
//! **把载荷拆成几张码连续显示**。后者是最后一条不依赖任何网络设施的路——用户在
//! 没有 WiFi、组播又被禁的场合只剩它。
//!
//! # 线格式没有变
//!
//! 帧号与帧数**从第一版起就写在信封里**（`Q2FA1:<帧号>/<帧数>:<BASE32>`），因此
//! 本模块不引入任何新的线格式：它只是第一次真的产出 `1/3`、`2/3`、`3/3` 这样的写法。
//! 这是当初把这两个字段放进格式的全部理由。
//!
//! ```text
//! Q2FA1:1/2:<前半段的 Base32>
//! Q2FA1:2/2:<后半段的 Base32>
//! ```
//!
//! # 本模块到二维码之间还差一步，那一步在 [`crate::qr`]
//!
//! [`encode_frames`] 交出的是**文本**，而文本要变成一张码还得走编码器。这两步之间
//! 有一个只有二维码才知道的量：一张码能装多少**载荷字节**（信封与 Base32 会膨胀，
//! 而多帧的帧头比单帧长）。因此「拆 + 渲染」的完整入口是
//! [`crate::qr::QrProfile::encode_payload_frames`]，它用的容量是
//! [`crate::qr::QrProfile::frame_payload_capacity`] ——**不要**拿单帧的
//! [`crate::qr::QrProfile::payload_capacity`] 去切帧，那样切出来的码会装不下
//! （见 `frame_payload_capacity` 的说明）。
//!
//! # 拼装凭什么知道「这几张码是同一份载荷」
//!
//! 这是本模块最要紧的一处判断，也是**唯一一处不能靠载荷自身认证兜住的地方**：拼错了
//! 字节，AEAD 会拒绝（那是载荷层的职责），但那时用户已经扫了五张码，而错误信息会是
//! 「解密失败」——一个把诊断引向「密钥不对」的方向。因此在拼装这一层要能**尽早**发现
//! 「这几张码不是一套」。
//!
//! 判据是一条来自编码方式的结构性事实：**除了最后一张，每张码都必须是满载的**。因为
//! 拆帧是按容量切出来的，所以
//!
//! - 第 1 到第 N−1 张的长度**恰好等于**容量；
//! - 第 N 张的长度在 `1..=容量` 之间；**唯一的例外是「只有一张」且载荷为空**
//!   （`Q2FA1:1/1:`）——那时没有「多切了一刀」可言，零字节就是全部内容。
//!
//! 最后那条例外不是给安全检查开的口子，而是把规则说准：`N ≥ 2` 时空帧只可能来自
//! 「编码方多切了一刀」，而那种码拼出来会**悄悄多出零字节**；`N = 1` 时空帧就是
//! 「载荷是空的」本身。拆帧侧同样只会在空载荷时产出这一种空帧（`chunks()` 永远
//! 不产出空块），因此两侧对「哪些帧集合合法」的答案完全一致——**能编出来的必定
//! 拼得回去**。
//!
//! 于是「用户先扫了 A 载荷的 1/3，又扫了 B 载荷的 2/3」这种交叉会被当场抓住：两者
//! 的容量不同（或同一容量下切点不同），第 2 张不是一个满载帧。**代价是拼装方必须
//! 知道容量**——而那个数字在扫码侧通常**拿不到**（它属于展示方的屏幕），因此扫码侧
//! 用 [`Reassembler::from_first_frame`]：满载长度从收到的第一帧**观察**得到，不做
//! 任何假定。
//!
//! 这条判据不是密码学意义上的认证，而是一道**廉价的形状检查**：它挡的是用户层面的
//! 混淆，不是攻击者。真正的认证始终在载荷的 AEAD 那一层。
//!
//! # 为什么不加校验和
//!
//! 想过在每一帧里放一个「属于哪一份载荷」的随机标识。放弃了：那要给线格式加第四个
//! 字段（帧号与帧数之外），而帧头一旦发出去就改不动；而它换来的只是让交叉更早被发现
//! ——上面那条结构性判据已经在同一个位置做到了这件事，且**不需要动格式**。
//!
//! 信封**不做校验和**这条规矩同样适用于这里：校验和给人的错觉是「校验过了所以它是真
//! 的」，而它防的其实只是抄错字符。

use crate::base32;
use crate::envelope;
use crate::error::{Error, Result};

/// 一份载荷拆出来的若干帧文本。
///
/// 返回的每一串都是一整段信封文本，可以交给 [`crate::qr::QrProfile`] 的
/// [`encode_payload_frames`](crate::qr::QrProfile::encode_payload_frames) 渲染，
/// 也可以交给平台的二维码库自己画（文本已经在信封格式里，任何编码器都认）。
///
/// # `capacity` 必须是**多帧**的容量
///
/// 它要满足「每一帧的信封文本都装得进对端那张码」。单帧容量（
/// [`crate::qr::QrProfile::payload_capacity`]）**不能**直接用在这里：帧数到两位数以上
/// 时帧头会长出 2–4 个字符（`255/255:` 比 `1/1:` 长 4 个），而单帧容量恰好是「再多一个
/// 字符就装不下」的位置。正确的数字是
/// [`crate::qr::QrProfile::frame_payload_capacity`]。
///
/// # 错误
///
/// - [`Error::TooManyFrames`]：需要的帧数超过 [`envelope::MAX_FRAMES`]。
/// - [`Error::PayloadTooLarge`]：`capacity` 为 0，而载荷非空——一张码装不下任何
///   字节的通道不是通道。`limit` 报 0，与「容量很小」共用同一条读法。
pub fn encode_frames(payload: &[u8], capacity: usize) -> Result<Vec<String>> {
    if payload.is_empty() {
        // 空载荷是**一张**码。零张码没法扫，而一张空码与单帧路径的行为一致
        // （`Q2FA1:1/1:`），因此这里不引入一种「空载荷要特殊处理」的分支。它也不必
        // 经过容量检查：空载荷不占字节。
        return Ok(vec![envelope::encode_frame(payload, 1, 1)]);
    }
    if capacity == 0 {
        return Err(Error::PayloadTooLarge {
            needed: payload.len(),
            limit: 0,
        });
    }

    let chunks = payload.len().div_ceil(capacity);
    if chunks > envelope::MAX_FRAMES as usize {
        return Err(Error::TooManyFrames {
            needed: chunks as u32,
            limit: envelope::MAX_FRAMES,
        });
    }

    let total = chunks as u32;
    Ok(payload
        .chunks(capacity)
        .enumerate()
        .map(|(offset, chunk)| envelope::encode_frame(chunk, offset as u32 + 1, total))
        .collect())
}

/// 从一张码的文本里读出的那一帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// 这是第几张（从 1 开始）。
    pub index: u32,
    /// 一共几张。
    pub total: u32,
    /// 这一张承载的字节。
    pub payload: Vec<u8>,
}

/// 逐张收集、拼回原来的载荷。
///
/// # 它是有状态的，因为扫码本来就是有状态的
///
/// 用户拿起手机对着屏幕扫：第一张可能糊了要重扫，顺序可能颠倒（如果用户按的不是
/// 顺序），同一张可能扫到两次。因此拼装器要能接受**任意顺序**、**重复**，并如实报出
/// 「还差哪几张」——那正是界面上要显示的东西。
///
/// # 那一张「满载帧」的长度是从第一帧**观察**来的
///
/// 判据是「除末帧外，每一帧都恰好满载」。而那个长度**不能**假定等于调用方给的容量：
/// 展示方可能把容量报大了（它报的是**载荷字节**上限，而实际拆帧时用的是同一个数字，
/// 但调用方完全可能传一个更保守的值），那时每一帧都会比容量短，而拼装器会把**正确
/// 的码**全部拒掉。因此：
///
/// - 容量已知时，它是一条**上界**（任何一帧都不得超过它）；
/// - 「满载帧多长」由收到的第一帧决定，之后所有非末帧都必须与它等长。
///
/// 这条规则与 [`Reassembler::new`] / [`Reassembler::from_first_frame`] 的差别无关：
/// 两个构造函数得到的是同一套检查，只是初值不同。
///
/// # 扫码侧该用哪个构造函数
///
/// **用 [`Reassembler::from_first_frame`]。** 容量属于**展示方**的屏幕
/// （[`crate::qr::QrProfile::frame_payload_capacity`]），扫码方拿不到它；而把自己
/// 这台设备的显示容量当作上界传进来，会拒掉大屏发来的**合法**帧——一台手机去扫
/// 一台桌面端的码，正是这个形状。只有在对端切点确实已知时（同一进程里的自测、
/// 或对端把容量带外告诉了你）才用 [`Reassembler::new`]。
///
/// # 容量传 0 是「还不知道」
///
/// [`Reassembler::new`] 收 0 时按「容量未知」处理（不做上界检查，长度全靠观察），
/// 而**不会**把每一帧都判成坏的。理由很直接：0 不是一个「很小的容量」，它是「还没
/// 拿到这个数字」——把调用方的缺席变成「所有码都是坏的」，会让一个本来能工作的流程
/// 彻底不可用，而错误信息还会指向二维码。
#[derive(Clone)]
pub struct Reassembler {
    /// 展示方声明的容量（载荷字节上限）。未知时是 `usize::MAX`。
    capacity: usize,
    /// 「满载帧」的长度，由收到的第一帧确定。
    unit: Option<usize>,
    /// 已经收到的帧内容，按帧号排列。缺失的位置是 `None`。
    ///
    /// 用 `Vec` 而不是 `HashMap`：帧号是稠密的，而最多 [`envelope::MAX_FRAMES`]
    /// （255）项。一个 255 项的 `Vec` 比一张哈希表小，且**迭代顺序天然确定**——那让
    /// 「还差哪几张」的输出稳定，界面上不会跳动。
    frames: Vec<Option<Vec<u8>>>,
    /// 第一帧告诉我们的总数。
    total: Option<u32>,
    /// 已经收到的张数。
    received: usize,
}

impl Reassembler {
    /// 造一个拼装器，`capacity` 是展示方说的每张码能装多少**载荷字节**。
    ///
    /// 它是一条**上界**而不是等号（见类型文档的「那一张『满载帧』的长度是从第一帧
    /// 观察来的」）。扫码方拿不到展示方的这个数字，因此那边应当用
    /// [`Reassembler::from_first_frame`]；传一个**偏小**的容量会把对端的合法帧拒掉。
    ///
    /// 传 0 表示「还不知道」：不做上界检查，满载帧的长度全靠观察。若确定自己不知道，
    /// 用 [`Reassembler::from_first_frame`] 更直白。
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: if capacity == 0 { usize::MAX } else { capacity },
            // 上限一次分配到位：255 个 `Option<Vec<u8>>` 是一张空指针表的大小，
            // 而按需增长会在最坏情况下反复搬移。
            frames: vec![None; envelope::MAX_FRAMES as usize],
            unit: None,
            total: None,
            received: 0,
        }
    }

    /// 造一个拼装器，**容量未知**：满载帧的长度由收到的第一帧决定。
    ///
    /// 给「扫码回调只拿到一串文本」的场景用（平台相机就是这样）。与
    /// [`Reassembler::new`]`(0)` 完全等价，单独一个构造函数是为了让调用点的意图
    /// 写在名字里，而不是写在一个 `0` 里。
    #[must_use]
    pub fn from_first_frame() -> Self {
        Self::new(0)
    }

    /// 展示方声明的容量（未知时是 [`usize::MAX`]）。
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// 「满载帧」的长度；还没收到任何一帧时是 `None`。
    #[must_use]
    pub const fn unit_len(&self) -> Option<usize> {
        self.unit
    }

    /// 一共要收几张；还没收到任何一张时是 `None`。
    #[must_use]
    pub const fn expected_frames(&self) -> Option<u32> {
        self.total
    }

    /// 已经收到几张。
    #[must_use]
    pub const fn received(&self) -> usize {
        self.received
    }

    /// 还差哪几张（帧号，升序）；还没收到任何一张时是空表。
    ///
    /// 返回的是**帧号**而不是下标，因为它要直接显示给用户（「还差第 2、3 张」）。
    #[must_use]
    pub fn missing(&self) -> Vec<u32> {
        let Some(total) = self.total else {
            return Vec::new();
        };
        (1..=total)
            .filter(|index| {
                self.frames
                    .get(*index as usize - 1)
                    .is_none_or(Option::is_none)
            })
            .collect()
    }

    /// 收下一张码的文本。
    ///
    /// 返回 `Ok(None)` 表示「这一张收下了，但还差别的」；`Ok(Some(payload))` 表示
    /// 「齐了，这是完整的载荷」。
    ///
    /// # 重复扫到同一张不算错误
    ///
    /// `Ok(None)` 且计数不变。用户扫完最后一张之后界面未必立刻收起来，而再扫一次是
    /// 正常的；把它报成错误会让界面弹出一个「这张码坏了」的提示，而码是好的。
    ///
    /// # 错误
    ///
    /// - [`Error::NotOurQrText`]：不是本应用的码。
    /// - [`Error::MalformedFrameHeader`]：帧头不合法。
    /// - [`Error::MalformedBase32`]：Base32 载荷不合法。
    /// - [`Error::FrameMismatch`]：这一张与之前那些**不是同一份载荷**（张数不同、
    ///   帧号越界、或者长度形状不对）。**拼装器在出错时保持原状**，因此用户可以继续
    ///   扫正确的那一张，不必从头再来。
    pub fn push(&mut self, text: &str) -> Result<Option<Vec<u8>>> {
        let (index, total, body) = envelope::decode_parts(text)?;
        // Base32 先解开：它是唯一一处会因「抄错字符」而失败的步骤，而它失败时拼装器
        // 不该有任何状态变化。
        let payload = base32::decode(body)?;
        self.accept_parts(index, total, payload)
    }

    /// 收下一帧已经解好的内容。
    ///
    /// # 错误
    ///
    /// 同 [`Reassembler::push`]（除了前三种解析错误）。
    pub fn accept(&mut self, frame: Frame) -> Result<Option<Vec<u8>>> {
        self.accept_parts(frame.index, frame.total, frame.payload)
    }

    /// 收下一帧的分字段形式。
    fn accept_parts(
        &mut self,
        index: u32,
        total: u32,
        payload: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        // ① 帧头自洽。与 [`envelope`] 的检查重复了一次，但这一层不能假定调用方一定
        //    是经过 `push` 进来的（`accept` 是公开的）。
        if total == 0 || total > envelope::MAX_FRAMES || index == 0 || index > total {
            return Err(Error::FrameMismatch);
        }

        // ② 这一帧若**不是末帧**，它就是一个 fullness 样本。把它一起交给检查，
        //    这样「这一帧」与「已经收到的那些」由同一条规则判定，不存在「先到的
        //    样本被后到的帧改变含义」这种需要额外状态的推理。
        let sample = if index != total {
            Some(payload.len())
        } else {
            None
        };
        self.check_consistent(index, total, payload.len(), sample)?;

        // ③ 重复扫到同一张：状态不变。
        let Some(slot) = self.frames.get_mut(index as usize - 1) else {
            // `check_consistent` 已经确认帧号在 `total` 之内、而 `total` 不超过
            // `MAX_FRAMES`，因此这个分支走不到。留着它是因为「走不到」这句话在依赖
            // 升级之后会失效，而那时一个 `unwrap` 就是一个 panic。
            return Err(Error::FrameMismatch);
        };
        if slot.is_some() {
            return Ok(None);
        }

        // ④ 写入状态。
        self.total = Some(total);
        if sample.is_some() {
            self.unit = sample;
        }
        *slot = Some(payload);
        self.received += 1;

        if self.received == total as usize {
            return Ok(Some(self.assemble()?));
        }
        Ok(None)
    }

    /// 检查「这一帧与已经收到的那些是不是同一份载荷」。
    ///
    /// # 判据
    ///
    /// 编码时是按固定长度切的，因此**唯一的合法形状**是：前 N−1 帧等长（记作 unit），
    /// 第 N 帧在 `1..=unit` 之间。所有检查都从这一条推出来，而不是另立一套规则：
    ///
    /// - **非末帧**：长度不得超过容量上界；若已经有过一个 fullness 样本，必须与它
    ///   等长。
    /// - **末帧**：不得超过容量上界；若有过多 fullness 样本则不得超过它。空帧只在
    ///   「只有一张码」时合法——见 `check_consistent` 里的说明。
    ///
    /// `sample` 是「这一帧如果是非末帧，它提供的那个长度」。把它作为参数传进来（而
    /// 不是在这里读 `self.unit`），是为了让**没有单元长度时**的推理不出现分叉：
    /// 帧可以乱序到达，而「先到的末帧」不能用来约束「后到的非末帧」。
    ///
    /// # 它拦的是用户层面的混淆，不是攻击者
    ///
    /// 交叉扫两份载荷时，unit 会立刻不匹配（两份载荷的切点不同），于是当场报错——而
    /// 这正是我们要的：不做这一步的话，拼出来的字节要到**载荷层的 AEAD** 那里才被
    /// 拒绝，报出来的是「解密失败」，一个把诊断引向「密钥不对」的错误方向。
    fn check_consistent(
        &self,
        index: u32,
        total: u32,
        len: usize,
        sample: Option<usize>,
    ) -> Result<()> {
        // 空帧只在「只有一张码」时合法：那时零字节就是全部内容（拆帧侧对空载荷也
        // 正是这么编的）。多帧里的空帧只可能来自「编码方多切了一刀」，而接受它等于
        // 让一份被悄悄改过的载荷过关。
        if len == 0 && total > 1 {
            return Err(Error::FrameMismatch);
        }
        if len > self.capacity {
            return Err(Error::FrameMismatch);
        }
        if let Some(known) = self.total
            && known != total
        {
            return Err(Error::FrameMismatch);
        }

        // 用「这一帧提供的样本（若有）」与「已观察到的」合并出一个 fullness：
        // 两者都在时它们必须相等，否则这两帧不是一套。
        let fullness = match (self.unit, sample) {
            (Some(known), Some(offer)) => {
                if known != offer {
                    return Err(Error::FrameMismatch);
                }
                Some(known)
            }
            (Some(known), None) => Some(known),
            (None, Some(offer)) => Some(offer),
            (None, None) => None,
        };

        match (index == total, fullness) {
            // 非末帧：必须恰好满载。
            (false, Some(unit)) if len != unit => Err(Error::FrameMismatch),
            // 末帧：不得超过满载长度。
            (true, Some(unit)) if len > unit => Err(Error::FrameMismatch),
            _ => Ok(()),
        }
    }

    /// 把收到的帧按顺序拼起来。
    fn assemble(&self) -> Result<Vec<u8>> {
        let total = self.total.ok_or(Error::FrameMismatch)? as usize;
        let mut out = Vec::new();
        for slot in self.frames.iter().take(total) {
            let Some(chunk) = slot else {
                // `received == total` 才走到这里，因此不可能缺。留着它是为了不让
                // 「不可能」变成一个 `unwrap`。
                return Err(Error::FrameMismatch);
            };
            out.extend_from_slice(chunk);
        }
        Ok(out)
    }
}

impl core::fmt::Debug for Reassembler {
    /// 只打印「收了几张、还差哪几张」。
    ///
    /// **绝不打印帧内容**：它来自攻击者可控的二维码文本，长度无界，且可能含隐私。
    /// 与 [`crate::envelope`] 的处理一致——防的是日志放大，不是秘密泄露。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reassembler")
            .field("expected", &self.total)
            .field("received", &self.received)
            .field("missing", &self.missing())
            .finish()
    }
}

/// 从一张码的文本里读出那一帧。
///
/// 与 [`envelope::decode`] 的区别只有一处：**多帧不再被拒绝**，而是被解出帧号与帧数。
/// 单帧（`1/1`）也走这条路，因此调用方只有一条路径要维护。
///
/// # 错误
///
/// 与 [`envelope::decode`] 相同，只是不再返回 [`Error::MultiFrameUnsupported`]。
pub fn decode_frame(text: &str) -> Result<Frame> {
    let (index, count, body) = envelope::decode_parts(text)?;
    Ok(Frame {
        index,
        total: count,
        payload: base32::decode(body)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拆出来的文本必须逐字节钉住。
    ///
    /// 手写期望值而不是编解码互相对照：互相对照只能证明自洽，对「两边一起改错」
    /// 完全盲——而帧头一旦发出去就改不动了。期望里的 Base32 取自 RFC 4648 §10 的
    /// 向量：`foo` → `MZXW6`、`bar` → `MJQXE`、`foobar` → `MZXW6YTBOI`。
    #[test]
    fn the_frame_texts_are_pinned() {
        // `foobar` 按 3 字节切两刀：`foo` 与 `bar`。
        let frames = encode_frames(b"foobar", 3).expect("拆得开");
        assert_eq!(frames, vec!["Q2FA1:1/2:MZXW6", "Q2FA1:2/2:MJQXE"]);

        // 切得整齐时**不会**多切出一个空帧。Base32 的每一位都取决于输入，因此这里
        // 只钉帧头（真正的线格式）与「恰好三帧」，字节本身由下面的往返测试保证。
        let frames = encode_frames(b"foobar", 2).expect("拆得开");
        assert_eq!(frames.len(), 3, "6 字节按 2 字节切是 3 帧，不是 4 帧");
        assert!(
            frames[0].starts_with("Q2FA1:1/3:") && frames[2].starts_with("Q2FA1:3/3:"),
            "帧头必须逐字节对：{frames:?}"
        );

        // 空载荷是一张码，且与单帧路径的写法一致。
        assert_eq!(encode_frames(b"", 3).expect("空载荷"), vec!["Q2FA1:1/1:"]);
    }

    /// 单帧仍然走同一条路，文本不变。
    ///
    /// 这条盯的是**向后兼容**：单帧的写法从第一版起就是 `1/1`，多帧实现不得改变它。
    #[test]
    fn a_single_frame_still_looks_the_same() {
        assert_eq!(
            encode_frames(b"foo", 100).expect("一帧够"),
            vec![envelope::encode(b"foo")]
        );
        let frame = decode_frame("Q2FA1:1/1:MZXW6").expect("解得开");
        assert_eq!(frame.index, 1);
        assert_eq!(frame.total, 1);
        assert_eq!(frame.payload, b"foo");
    }

    /// **随便什么顺序扫都能拼回来。**
    ///
    /// 这是拼装器存在的理由：用户不可能保证按顺序扫。
    #[test]
    fn frames_reassemble_in_any_order() {
        let payload: Vec<u8> = (0..=255_u8).cycle().take(1000).collect();
        let frames = encode_frames(&payload, 64).expect("拆得开");
        assert!(frames.len() > 4, "这份载荷应当拆成好几帧");

        // 逆序。
        let mut reassembler = Reassembler::new(64);
        let mut result = None;
        for text in frames.iter().rev() {
            result = reassembler.push(text).expect("每一张都该被收下");
        }
        assert_eq!(result.expect("应当拼齐"), payload);

        // 从中间开始，绕一圈。
        let mut reassembler = Reassembler::new(64);
        let mut result = None;
        for offset in 0..frames.len() {
            let text = &frames[(offset + 3) % frames.len()];
            result = reassembler.push(text).expect("每一张都该被收下");
        }
        assert_eq!(result.expect("应当拼齐"), payload);
    }

    /// 重复扫到同一张不算错误，也不改变计数。
    #[test]
    fn scanning_the_same_frame_twice_is_not_an_error() {
        let frames = encode_frames(b"hello world", 4).expect("拆得开");
        let mut reassembler = Reassembler::new(4);

        assert_eq!(reassembler.push(&frames[0]).expect("第一张"), None);
        assert_eq!(reassembler.received(), 1);
        assert_eq!(reassembler.expected_frames(), Some(3));

        // 同一张再来三次。
        for _ in 0..3 {
            assert_eq!(reassembler.push(&frames[0]).expect("重复不算错"), None);
        }
        assert_eq!(reassembler.received(), 1, "重复不该把计数推上去");
        assert_eq!(reassembler.missing(), vec![2, 3]);
    }

    /// 「还差哪几张」必须准确，且**升序**。
    ///
    /// 那是界面上要显示的东西；顺序不稳定会让它跳动。
    #[test]
    fn the_missing_list_is_accurate_and_sorted() {
        let frames = encode_frames(&[0_u8; 100], 10).expect("拆得开");
        assert_eq!(frames.len(), 10);

        let mut reassembler = Reassembler::new(10);
        assert_eq!(reassembler.expected_frames(), None, "还没扫之前不知道总数");
        assert!(reassembler.missing().is_empty());

        reassembler.push(&frames[0]).expect("第一张");
        assert_eq!(reassembler.missing(), (2..=10).collect::<Vec<u32>>());

        reassembler.push(&frames[4]).expect("第五张");
        reassembler.push(&frames[9]).expect("第十张");
        assert_eq!(
            reassembler.missing(),
            vec![2, 3, 4, 6, 7, 8, 9],
            "缺的那几张必须按帧号升序（3 是「第三张」，不是下标 3）"
        );
    }

    /// **「前 N−1 帧等长」这条判据真的会拒绝东西。**
    ///
    /// 两个方向各来一次：非末帧短了、非末帧长了。它们对应的是「用户交叉扫了两份
    /// 切点不同的载荷」。
    #[test]
    fn the_fullness_rule_rejects_mismatched_frames() {
        let a = encode_frames(&[0xAA_u8; 30], 8).expect("拆得开"); // 8/8/8/6

        // 短了：A 的末帧（6 字节）被放到第 3 个位置，而第 3 帧必须是 8 字节。
        let mut short = Reassembler::new(8);
        short.push(&a[0]).expect("A 的第一张");
        short.push(&a[1]).expect("A 的第二张");
        let result = short.accept(Frame {
            index: 3,
            total: 4,
            payload: vec![0xAA; 6],
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "非末帧必须满载，6 字节的第 3 帧应当被抓住，实际 {result:?}"
        );
        // 出错之后拼装器**保持原状**，用户可以接着扫正确的那一张。
        assert_eq!(short.received(), 2);
        short.push(&a[2]).expect("接着扫 A 是对的");
        assert!(short.push(&a[3]).expect("最后一张").is_some());

        // 长了：第 2 帧有 9 字节，超过容量 8。
        let mut long = Reassembler::new(8);
        long.push(&a[0]).expect("A 的第一张");
        let result = long.accept(Frame {
            index: 2,
            total: 4,
            payload: vec![0xAA; 9],
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "超过容量的帧应当被抓住，实际 {result:?}"
        );
    }

    /// **同长度的两份载荷在这一层无法区分——这是刻意的边界，不是缺陷。**
    ///
    /// 格式里没有「我属于哪一份载荷」这个字段（见模块文档里「为什么不加校验和」）。
    /// 因此两份**总长相同、切点相同**的载荷互换帧时，拼装层看不出任何异常——拼出来
    /// 的字节是错的，而**载荷层的 AEAD 会拒绝它**。
    ///
    /// 把这条测试写下来，是为了不让后人误以为拼装层能替代载荷认证：它是一道防用户
    /// 混淆的廉价形状检查，不是密码学意义上的认证。
    #[test]
    fn two_identically_shaped_payloads_are_indistinguishable_here() {
        let a = encode_frames(&[0xAA_u8; 24], 8).expect("拆得开");
        let b = encode_frames(&[0xBB_u8; 24], 8).expect("拆得开");
        assert_eq!(a.len(), b.len(), "两份形状相同，都是三帧 8 字节");

        let mut reassembler = Reassembler::new(8);
        reassembler.push(&a[0]).expect("A 的第一张");
        reassembler
            .push(&b[1])
            .expect("B 的第二张——长度一样，这里看不出来");
        let done = reassembler
            .push(&a[2])
            .expect("A 的第三张")
            .expect("三帧齐了");

        // 拼出来的东西**既不是 A 也不是 B**，而是一个混合体。拼装层没有任何办法
        // 发现它——那是载荷层 AEAD 的职责。
        assert_eq!(done.len(), 24);
        assert_ne!(done, vec![0xAA_u8; 24]);
        assert_ne!(done, vec![0xBB_u8; 24]);
        assert_eq!(done[..8], [0xAA_u8; 8]);
        assert_eq!(done[8..16], [0xBB_u8; 8]);
        assert_eq!(done[16..], [0xAA_u8; 8]);
    }

    /// 两份载荷的张数不同时，也要能被抓住。
    #[test]
    fn a_different_frame_count_is_caught() {
        let a = encode_frames(&[0xAA_u8; 30], 8).expect("拆得开"); // 4 帧
        let b = encode_frames(&[0xBB_u8; 10], 8).expect("拆得开"); // 2 帧

        let mut reassembler = Reassembler::new(8);
        reassembler.push(&a[0]).expect("A 的第一张");
        let result = reassembler.push(&b[0]);
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "张数不同必须被抓住，实际 {result:?}"
        );
    }

    /// 帧号与帧数不自洽（0、越界）一律拒绝。
    #[test]
    fn impossible_frame_numbers_are_rejected() {
        let mut reassembler = Reassembler::new(8);
        for (index, total) in [(0_u32, 1_u32), (1, 0), (3, 2), (2, 1), (300, 1)] {
            let frame = Frame {
                index,
                total,
                payload: vec![0; 8],
            };
            let result = reassembler.accept(frame);
            assert!(
                matches!(result, Err(Error::FrameMismatch)),
                "{index}/{total} 应当被拒绝，实际 {result:?}"
            );
        }
        assert_eq!(reassembler.received(), 0);
    }

    /// **多帧里的空帧必须被拒绝，单帧里的空帧不是错误。**
    ///
    /// 多帧里的空末帧意味着「编码方多切了一刀」，而那种码拼出来的载荷会多出零字节
    /// ——一份被静默改变的载荷。单帧（`1/1`）没有这个歧义：它就是「载荷是空的」，
    /// 而拆帧侧对空载荷也正是这么编的（`encode_frames` 的文档）。两侧必须一致，否则
    /// 本模块会编出一张自己对端拒收的码。
    #[test]
    fn an_empty_frame_is_only_legal_when_it_is_the_whole_payload() {
        // 多帧里的空末帧：拒绝。
        let mut reassembler = Reassembler::new(8);
        reassembler
            .accept(Frame {
                index: 1,
                total: 2,
                payload: vec![1; 4],
            })
            .expect("第一张");
        let result = reassembler.accept(Frame {
            index: 2,
            total: 2,
            payload: Vec::new(),
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "多帧里的空末帧必须被拒绝，实际 {result:?}"
        );

        // 多帧里的空**首**帧同样拒绝（它连「末帧」都不是）。
        let mut reassembler = Reassembler::new(8);
        let result = reassembler.accept(Frame {
            index: 1,
            total: 2,
            payload: Vec::new(),
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "多帧里的空首帧必须被拒绝，实际 {result:?}"
        );

        // 单帧的空载荷：接受，且拼出来就是零字节。
        let mut reassembler = Reassembler::new(8);
        let done = reassembler
            .accept(Frame {
                index: 1,
                total: 1,
                payload: Vec::new(),
            })
            .expect("空载荷是合法的单帧");
        assert_eq!(done.expect("一张就齐了"), Vec::<u8>::new());
        assert!(reassembler.missing().is_empty());

        // 拆帧侧编出来的那张空码，必须能被同一个拼装器收下。
        let frames = encode_frames(b"", 8).expect("空载荷是一张码");
        let mut reassembler = Reassembler::new(8);
        let done = reassembler.push(&frames[0]).expect("自己编的必须收得下");
        assert_eq!(done.expect("一张就齐了"), Vec::<u8>::new());
    }

    /// 容量未知时，满载帧的长度由**第一帧**确定。
    ///
    /// 这是 `from_first_frame` 的全部内容，也是「扫码回调只拿到一串文本」那种场景的
    /// 正确行为：不假定任何容量，只要求「前 N−1 帧等长」。
    #[test]
    fn an_unknown_capacity_derives_the_unit_from_the_first_frame() {
        let mut reassembler = Reassembler::from_first_frame();
        assert_eq!(reassembler.capacity(), usize::MAX, "未知容量不做上界检查");
        assert_eq!(reassembler.unit_len(), None);

        reassembler
            .accept(Frame {
                index: 1,
                total: 2,
                payload: vec![1; 5],
            })
            .expect("第一帧给出了 unit");
        assert_eq!(reassembler.unit_len(), Some(5), "unit 应当来自第一帧");

        // 第二帧（末帧）比 unit 短 → 可以；比 unit 长 → 拒绝。
        let too_long = Reassembler::from_first_frame();
        let mut too_long = {
            let mut it = too_long;
            it.accept(Frame {
                index: 1,
                total: 2,
                payload: vec![1; 5],
            })
            .expect("第一帧");
            it
        };
        let result = too_long.accept(Frame {
            index: 2,
            total: 2,
            payload: vec![2; 9],
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "末帧长于 unit 必须被拒绝，实际 {result:?}"
        );

        let done = reassembler
            .accept(Frame {
                index: 2,
                total: 2,
                payload: vec![2; 3],
            })
            .expect("末帧短于 unit 是合法的");
        assert_eq!(done.expect("拼齐"), [vec![1_u8; 5], vec![2_u8; 3]].concat());
    }

    /// **非末帧必须等长**，与是否知道容量无关。
    ///
    /// 这条是「这几张码是同一份载荷」的判据本身：两份载荷的切点不同，因此交叉扫的
    /// 那一刻 unit 就会不匹配。
    #[test]
    fn non_final_frames_must_all_be_the_same_length() {
        let mut reassembler = Reassembler::from_first_frame();
        reassembler
            .accept(Frame {
                index: 1,
                total: 3,
                payload: vec![1; 8],
            })
            .expect("第一帧 8 字节");
        let result = reassembler.accept(Frame {
            index: 2,
            total: 3,
            payload: vec![2; 7],
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "第二帧只有 7 字节，必须被拒绝，实际 {result:?}"
        );
        assert_eq!(reassembler.received(), 1, "出错时状态不变");
    }

    /// 帧数超过上限时如实报「需要多少帧、上限多少帧」。
    #[test]
    fn too_many_frames_reports_the_frame_counts() {
        // 256 字节按 1 字节切是 256 帧 > 255（`MAX_FRAMES`）。
        let result = encode_frames(&vec![0_u8; 256], 1);
        match result {
            Err(Error::TooManyFrames { needed, limit }) => {
                assert_eq!(needed, 256);
                assert_eq!(limit, envelope::MAX_FRAMES);
            }
            other => panic!("应当报帧数超过上限，实际 {other:?}"),
        }

        // 255 字节按 1 字节切恰好是 255 帧，在上限之内。
        let frames = encode_frames(&vec![0_u8; 255], 1).expect("刚好在上限之内");
        assert_eq!(frames.len(), 255);
        assert_eq!(frames[254], "Q2FA1:255/255:AA");
        // 帧号是十进制，位数会变；因此第一帧是 `1/255` 而不是 `001/255`。
        assert_eq!(frames[0], "Q2FA1:1/255:AA");
    }

    /// 容量为 0 的拆帧请求必须被拒绝，且报的是**载荷字节**。
    ///
    /// 它曾经借用 [`Error::BadRenderGeometry`]（渲染参数不合法）——那是个分类错误：
    /// 缩放与静区是**画**的时候的参数，与「一份载荷能不能切开」毫无关系。
    #[test]
    fn encoding_into_a_zero_capacity_is_rejected() {
        let result = encode_frames(b"x", 0);
        match result {
            Err(Error::PayloadTooLarge { needed, limit }) => {
                assert_eq!(needed, 1);
                assert_eq!(limit, 0);
            }
            other => panic!("应当报「装不下」，实际 {other:?}"),
        }
        // 空载荷不占字节，因此容量为 0 也仍然是**一张**码——它不是「装不下」。
        assert_eq!(encode_frames(b"", 0).expect("空载荷"), vec!["Q2FA1:1/1:"]);
    }

    /// 不是本应用的码要报「不是我们的」，而不是「帧头坏了」。
    #[test]
    fn foreign_text_is_reported_as_foreign() {
        for text in ["hello", "Q2FA2:1/1:MZXW6", "https://example.com"] {
            let result = decode_frame(text);
            assert!(
                matches!(result, Err(Error::NotOurQrText)),
                "{text} 应当报「不是我们的码」，实际 {result:?}"
            );
        }
    }

    /// 调试输出只打印计数，**绝不打印帧内容**。
    #[test]
    fn debug_does_not_dump_frames() {
        let mut reassembler = Reassembler::new(8);
        reassembler
            .push("Q2FA1:1/2:MZXW6YTBOI")
            .expect("第一张收下");
        let text = format!("{reassembler:?}");
        assert!(text.contains("expected: Some(2)"), "实际 {text}");
        assert!(text.contains("received: 1"), "实际 {text}");
        // Base32 的内容与解出来的字节都不该出现。
        assert!(!text.contains("MZXW6"), "帧文本泄露进了 Debug：{text}");
        assert!(!text.contains("foo"), "帧内容泄露进了 Debug：{text}");
    }

    /// 一份载荷拆开再拼回来必须**逐字节相同**（属性测试的确定性版本）。
    ///
    /// 容量取到 1 是有意的：那是**帧数最多的那一端**（同时也正好落在
    /// [`envelope::MAX_FRAMES`] 之内，见下）。容量取到大于载荷，则是另一端。
    #[test]
    fn every_capacity_round_trips() {
        // 200 字节：按容量 1 切是 200 帧，在 `MAX_FRAMES`（255）之内。**不能取 300**
        // ——那按容量 1 切是 300 帧，会被如实拒掉（而那不是本测试要验的性质）。
        let payload: Vec<u8> = (0..=255_u8).cycle().take(200).collect();
        for capacity in [1_usize, 2, 3, 7, 64, 199, 200, 201, 1000] {
            let frames = encode_frames(&payload, capacity).expect("拆得开");
            let mut reassembler = Reassembler::new(capacity);
            let mut result = None;
            for text in &frames {
                result = reassembler.push(text).expect("每一张都该被收下");
            }
            assert_eq!(
                result.expect("应当拼齐"),
                payload.as_slice(),
                "容量 {capacity} 下往返不一致"
            );
        }
    }
}
