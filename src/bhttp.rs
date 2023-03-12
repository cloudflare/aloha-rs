// Copyright (c) 2022-2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or
// at http://www.apache.org/licenses/LICENSE-2.0

//! A RFC 9292 implementation that has chained parser and builder to
//! avoid heap allocation.
//!
//! To build a bHTTP message, start with a [`Builder`] and a choice of
//! [`Framing`], advance the builder by calling vairous `push_`
//! functions with necessary data, the builder will transit into
//! another.
//!
//! Similar, to parse a bHTTP message, start with a [`Parser`], then
//! move to the next parser in the chain by calling the `next`
//! function.
//!
//! # Examples
//! Build a bHTTP request:
//! ```
//! use aloha::bhttp::{Builder, Error, Framing};
//!
//! # fn main() -> Result<(), Error> {
//! let mut buf = Vec::new();
//! Builder::new(&mut buf, Framing::KnownLenReq)
//!     .push_ctrl(b"GET", b"https", b"www.example.com", b"/hello.txt")?
//!     .push_headers(&[
//!         (
//!             &b"user-agent"[..],
//!             &b"curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"[..],
//!         ),
//!         (&b"host"[..], &b"www.example.com"[..]),
//!         (&b"accept-language"[..], &b"en, mi"[..]),
//!     ])?;
//! # Ok(())
//! # }
//! ```
//!
//! Parse a bHTTP response:
//! ```no_run
//! use aloha::bhttp::{Error, Framing, Parser};
//!
//! # fn main() -> Result<(), Error> {
//! # let some_buf = &[];
//! let parser = Parser::new(some_buf);
//! let req_ctrl = parser.next_req()?;
//! let ctrl = req_ctrl.get()?;
//! assert_eq!(b"GET", ctrl.method);
//! assert_eq!(b"https", ctrl.scheme);
//! assert_eq!(b"example.com", ctrl.authority);
//! assert_eq!(b"/", ctrl.path);
//! let headers = req_ctrl.next()?;
//! // ...
//! # Ok(())
//! # }
//! ```

use bytes::{Buf, BufMut};
use thiserror::Error as ThisError;

mod builder;
mod parser;

pub use builder::*;
pub use parser::*;

const CONTENT_TERMINATOR: u8 = 0x00;

/// Errors used in bHTTP library.
#[derive(ThisError, Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// Provided buffer is too short.
    #[error("Provided buffer is too short")]
    ShortBuf,
    /// Input data is invalid.
    #[error("Input data is invalid")]
    InvalidInput,
    /// Unexpected state in message builder.
    #[error("Unexpected state in message builder")]
    UnexpectedBuildState,
    /// Unexpected framing.
    #[error("Unexpected framing")]
    UnexpectedFraming,
}

type Result<T> = std::result::Result<T, Error>;

/// Represent the framing byte in the bHTTP message.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum Framing {
    /// Known Length Request
    KnownLenReq = 0,
    /// Known Length Response
    KnownLenRes = 1,
    /// Indeterminate Length Request
    IndLenReq = 2,
    /// Indeterminate Length Reponse
    IndLenRes = 3,
}

impl Framing {
    /// Whether the framing stands for a known-lengthed message.
    pub fn known_len(&self) -> bool {
        *self == Self::KnownLenReq || *self == Self::KnownLenRes
    }

    /// Whether the framing stands for request message.
    pub fn is_request(&self) -> bool {
        *self == Self::KnownLenReq || *self == Self::IndLenReq
    }
}

impl TryFrom<u8> for Framing {
    type Error = Error;
    fn try_from(n: u8) -> Result<Self> {
        match n {
            0 => Ok(Self::KnownLenReq),
            1 => Ok(Self::KnownLenRes),
            2 => Ok(Self::IndLenReq),
            3 => Ok(Self::IndLenRes),
            _ => Err(Error::InvalidInput),
        }
    }
}

fn is_final_ctrl(status: usize) -> bool {
    status >= 200
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct VarInt(u64);

impl VarInt {
    const MAX: u64 = (1 << 62) - 1;

    fn as_usize(&self) -> usize {
        self.0 as usize
    }

    fn size(&self) -> usize {
        match self.0 {
            0..=0x3f => 1,
            0x40..=0x3fff => 2,
            0x4000..=0x3fff_ffff => 3,
            0x4000_0000.. => 4,
        }
    }
}

impl From<VarInt> for u64 {
    fn from(v: VarInt) -> Self {
        v.0
    }
}

impl TryFrom<u64> for VarInt {
    type Error = Error;
    fn try_from(n: u64) -> Result<Self> {
        if n > Self::MAX {
            Err(Error::InvalidInput)
        } else {
            Ok(Self(n))
        }
    }
}

impl TryFrom<usize> for VarInt {
    type Error = Error;
    fn try_from(n: usize) -> Result<Self> {
        let n = u64::try_from(n).map_err(|_| Error::InvalidInput)?;
        Self::try_from(n)
    }
}

impl VarInt {
    /// Parse VarInt from a byte slice.
    fn parse<B: Buf>(buf: &mut B) -> Result<Self> {
        if !buf.has_remaining() {
            return Err(Error::InvalidInput);
        }
        let b = buf.chunk()[0];
        let n = 1 << (b >> 6);
        if buf.remaining() < n {
            return Err(Error::InvalidInput);
        }
        Ok(Self(match n {
            1 => (buf.get_u8() & ((1 << 6) - 1)).into(),
            2 => (buf.get_u16() & ((1 << 14) - 1)).into(),
            4 => (buf.get_u32() & ((1 << 30) - 1)).into(),
            8 => buf.get_u64() & ((1 << 62) - 1),
            _ => unreachable!(),
        }))
    }

    /// Compose into bytes.
    fn compose<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        let len = buf.remaining_mut();
        match self.0 {
            0..=0x3f if len > 0 => buf.put_u8(self.0 as u8),
            0x40..=0x3fff if len > 1 => buf.put_u16((self.0 | (0b01 << 14)) as u16),
            0x4000..=0x3fff_ffff if len > 3 => buf.put_u32((self.0 | (0b10 << 30)) as u32),
            0x4000_0000..=0x3fff_ffff_ffff_ffff if len >= 8 => buf.put_u64(self.0 | (0b11 << 62)),
            Self::MAX.. => return Err(Error::InvalidInput),
            _ => return Err(Error::ShortBuf),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rstest::*;
    use std::str::from_utf8;

    pub(crate) fn unwrap_fieldline<'a>(
        f: Option<Result<(&'a [u8], &'a [u8])>>,
    ) -> (&'a str, &'a str) {
        let (k, v) = f.unwrap().unwrap();
        (from_utf8(k).unwrap(), from_utf8(v).unwrap())
    }

    pub(crate) const EXAMPLE_KNOWN_LEN_REQ1: &[u8] = hex!(
        "
        00034745 54056874 7470730b 6578616d
        706c652e 636f6d01 2f
        "
    )
    .as_slice();

    // https://www.rfc-editor.org/rfc/rfc9292#name-request-example
    pub(crate) const EXAMPLE_KNOWN_LEN_REQ2: &[u8] = hex!(
        "
        00034745 54056874 74707300 0a2f6865
        6c6c6f2e 74787440 6c0a7573 65722d61
        67656e74 34637572 6c2f372e 31362e33
        206c6962 6375726c 2f372e31 362e3320
        4f70656e 53534c2f 302e392e 376c207a
        6c69622f 312e322e 3304686f 73740f77
        77772e65 78616d70 6c652e63 6f6d0f61
        63636570 742d6c61 6e677561 67650665
        6e2c206d 690000
        "
    )
    .as_slice();

    // https://www.rfc-editor.org/rfc/rfc9292#name-request-example
    pub(crate) const EXAMPLE_IND_LEN_REQ1: &[u8] = hex!(
        "
        02034745 54056874 74707300 0a2f6865
        6c6c6f2e 7478740a 75736572 2d616765
        6e743463 75726c2f 372e3136 2e33206c
        69626375 726c2f37 2e31362e 33204f70
        656e5353 4c2f302e 392e376c 207a6c69
        622f312e 322e3304 686f7374 0f777777
        2e657861 6d706c65 2e636f6d 0f616363
        6570742d 6c616e67 75616765 06656e2c
        206d6900 00000000 00000000 00000000
        "
    )
    .as_slice();

    pub(crate) const EXAMPLE_IND_LEN_REQ2: &[u8] = hex!(
        "
        02034745 54056874 74707300 0a2f6865
        6c6c6f2e 7478740a 75736572 2d616765
        6e743463 75726c2f 372e3136 2e33206c
        69626375 726c2f37 2e31362e 33204f70
        656e5353 4c2f302e 392e376c 207a6c69
        622f312e 322e3304 686f7374 0f777777
        2e657861 6d706c65 2e636f6d 0f616363
        6570742d 6c616e67 75616765 06656e2c
        206d6900
        "
    )
    .as_slice();

    // https://www.rfc-editor.org/rfc/rfc9292#name-response-example
    pub(crate) const EXAMPLE_KNOWN_LEN_RES1: &[u8] = hex!(
        "
        0140c800 1d546869 7320636f 6e74656e
        7420636f 6e746169 6e732043 524c462e
        0d0a0d07 74726169 6c657204 74657874
        "
    )
    .as_slice();

    // https://www.rfc-editor.org/rfc/rfc9292#name-response-example
    pub(crate) const EXAMPLE_IND_LEN_RES1: &[u8] = hex!(
        "
        03406607 72756e6e 696e670a 22736c65
        65702031 35220040 67046c69 6e6b233c
        2f737479 6c652e63 73733e3b 2072656c
        3d707265 6c6f6164 3b206173 3d737479
        6c65046c 696e6b24 3c2f7363 72697074
        2e6a733e 3b207265 6c3d7072 656c6f61
        643b2061 733d7363 72697074 0040c804
        64617465 1d4d6f6e 2c203237 204a756c
        20323030 39203132 3a32383a 35332047
        4d540673 65727665 72064170 61636865
        0d6c6173 742d6d6f 64696669 65641d57
        65642c20 3232204a 756c2032 30303920
        31393a31 353a3536 20474d54 04657461
        67142233 34616133 38372d64 2d313536
        38656230 30220d61 63636570 742d7261
        6e676573 05627974 65730e63 6f6e7465
        6e742d6c 656e6774 68023531 04766172
        790f4163 63657074 2d456e63 6f64696e
        670c636f 6e74656e 742d7479 70650a74
        6578742f 706c6169 6e003348 656c6c6f
        20576f72 6c642120 4d792063 6f6e7465
        6e742069 6e636c75 64657320 61207472
        61696c69 6e672043 524c462e 0d0a0000
        "
    )
    .as_slice();

    #[rstest]
    #[case(&[0x00], Ok(0x00))]
    #[case(&[0x01, 0x02, 0x03], Ok(0x01))]
    #[case(&[0x40, 0xff], Ok(0xff))]
    #[case(&[0x80, 0xad, 0xbe, 0xef], Ok(0x00adbeef))]
    #[case(&[0xc0], Err(Error::InvalidInput))]
    fn varint_parse(#[case] slice: &[u8], #[case] exp: Result<u64>) {
        let mut buf = slice;
        assert_eq!(exp, VarInt::parse(&mut buf).map(|v| v.into()))
    }

    #[rstest]
    #[case(0x00, 1, Ok(&hex!("00")[..]))]
    #[case(0x3f, 1, Ok(&hex!("3f")[..]))]
    #[case(1 << 8, 2, Ok(&hex!("4100")[..]))]
    #[case(1 << 16, 4, Ok(&hex!("80010000")[..]))]
    #[case(1 << 32, 8, Ok(&hex!("c000000100000000")[..]))]
    #[case(1 << 16, 1, Err(Error::ShortBuf))]
    fn varint_compose(#[case] num: u64, #[case] buf_len: usize, #[case] exp_hex: Result<&[u8]>) {
        let mut buf = vec![0xff; buf_len];
        let mut slice_mut = buf.as_mut_slice();
        let len = slice_mut.len();
        let r = VarInt::try_from(num).unwrap().compose(&mut slice_mut);
        let new_len = slice_mut.len();

        assert_eq!(exp_hex, r.map(|_| &buf[..len - new_len]));
    }
}
