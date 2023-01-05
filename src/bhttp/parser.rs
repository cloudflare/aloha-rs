// All the iterators are fused, so the consumed len can be accquired
// later.

use super::*;
use std::fmt;

macro_rules! consumed {
    ($iter:expr) => {{
        let n = $iter.slice.len();
        let mut err = None;
        while let Some(v) = $iter.next() {
            match v {
                Ok(_) => {}
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        match err {
            Some(e) => Err(e),
            None => Ok(n - $iter.slice.len()),
        }
    }};
}

macro_rules! iter_bail {
    ($self:expr, $e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                $self.done = true;
                return Some(Err(e));
            }
        }
    };
}

/// Entrypoint to parse a bHTTP message.
#[derive(Clone, Copy)]
pub struct Parser<'a> {
    slice: &'a [u8],
}

impl<'a> Parser<'a> {
    /// Create a new parser.
    pub fn new(slice: &'a [u8]) -> Self {
        Self { slice }
    }

    /// Parse the framing from the buffer.
    pub fn framing(&self) -> Result<Framing> {
        if self.slice.is_empty() {
            return Err(Error::ShortBuf);
        }
        Framing::try_from(self.slice[0])
    }

    /// Consume the parser, and convert it into a request control data
    /// parser.
    pub fn next_req(mut self) -> Result<ReqCtrlParser<'a>> {
        let framing = self.framing()?;
        if !framing.is_request() {
            return Err(Error::UnexpectedFraming);
        }
        self.slice.advance(1);
        Ok(ReqCtrlParser {
            slice: self.slice,
            framing,
        })
    }

    /// Consume the parser, and convert it into a response control data
    /// parser.
    pub fn next_res(mut self) -> Result<ResCtrlParser<'a>> {
        let framing = self.framing()?;
        if framing.is_request() {
            return Err(Error::UnexpectedFraming);
        }
        self.slice.advance(1);
        Ok(ResCtrlParser {
            slice: self.slice,
            framing,
        })
    }
}

/// Request control data parser.
#[derive(Clone, Copy)]
pub struct ReqCtrlParser<'a> {
    slice: &'a [u8],
    framing: Framing,
}

impl<'a> ReqCtrlParser<'a> {
    /// Parse and return the request control data.
    pub fn get(&self) -> Result<ReqCtrl> {
        let mut slice = self.slice;
        let method = get_sized(&mut slice)?;
        let scheme = get_sized(&mut slice)?;
        let authority = get_sized(&mut slice)?;
        let path = get_sized(&mut slice)?;
        Ok(ReqCtrl {
            method,
            scheme,
            authority,
            path,
        })
    }

    /// Consume the parser, and create a parser for headers.
    pub fn next(mut self) -> Result<HeaderParser<'a>> {
        get_sized(&mut self.slice)?;
        get_sized(&mut self.slice)?;
        get_sized(&mut self.slice)?;
        get_sized(&mut self.slice)?;
        Ok(HeaderParser {
            slice: self.slice,
            framing: self.framing,
        })
    }
}

/// Request control data.
#[derive(Clone, Copy)]
pub struct ReqCtrl<'a> {
    /// method
    pub method: &'a [u8],
    /// scheme
    pub scheme: &'a [u8],
    /// authority
    pub authority: &'a [u8],
    /// path
    pub path: &'a [u8],
}

/// Response control data parser.
#[derive(Clone, Copy)]
pub struct ResCtrlParser<'a> {
    slice: &'a [u8],
    framing: Framing,
}

impl<'a> ResCtrlParser<'a> {
    /// Iterator over the informational and final control data.
    pub fn iter(&self) -> ResCtrlIter {
        ResCtrlIter {
            slice: self.slice,
            framing: self.framing,
            done: false,
        }
    }

    /// Consume the parser, and create a parser for headers.
    pub fn next(self) -> Result<HeaderParser<'a>> {
        let mut iter = self.iter();
        let n = consumed!(iter)?;
        Ok(HeaderParser {
            slice: &self.slice[n..],
            framing: self.framing,
        })
    }
}

/// Iterator over items in response control data.
pub struct ResCtrlIter<'a> {
    slice: &'a [u8],
    framing: Framing,
    done: bool,
}

impl<'a> Iterator for ResCtrlIter<'a> {
    type Item = Result<(usize, Option<FieldIter<'a>>)>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let status = iter_bail!(self, VarInt::parse(&mut self.slice)).as_usize();

        if is_final_ctrl(status) {
            self.done = true;
            return Some(Ok((status, None)));
        }

        // calculate the offset
        let mut iter = FieldIter {
            slice: self.slice,
            framing: self.framing,
            done: false,
            len: None,
        };
        let n = iter_bail!(self, consumed!(iter));

        let iter = FieldIter {
            slice: self.slice,
            framing: self.framing,
            done: false,
            len: None,
        };

        self.slice.advance(n);
        Some(Ok((status, Some(iter))))
    }
}

/// Parser for header section.
#[derive(Clone, Copy)]
pub struct HeaderParser<'a> {
    slice: &'a [u8],
    framing: Framing,
}

impl<'a> HeaderParser<'a> {
    /// Return an iterator over each header.
    pub fn iter(&self) -> FieldIter {
        let truncated = self.slice.is_empty();
        FieldIter {
            slice: self.slice,
            framing: self.framing,
            done: truncated,
            len: None,
        }
    }

    /// Consume current parser, and return a new one for content.
    pub fn next(self) -> Result<ContentParser<'a>> {
        let mut iter = self.iter();
        let n = consumed!(iter)?;
        Ok(ContentParser {
            slice: &self.slice[n..],
            framing: self.framing,
        })
    }
}

/// Parser for content.
#[derive(Clone, Copy)]
pub struct ContentParser<'a> {
    slice: &'a [u8],
    framing: Framing,
}

impl<'a> ContentParser<'a> {
    /// Return an iterator over each content chunk.
    pub fn iter(&self) -> ContentIter {
        let truncated = self.slice.is_empty();
        ContentIter {
            slice: self.slice,
            framing: self.framing,
            done: truncated,
        }
    }

    /// Consume current parser, and return a new one for tailers.
    pub fn next(self) -> Result<TailerParser<'a>> {
        let mut iter = self.iter();
        let n = consumed!(iter)?;
        Ok(TailerParser {
            slice: &self.slice[n..],
            framing: self.framing,
        })
    }
}

/// Iterator for content chunks.
pub struct ContentIter<'a> {
    slice: &'a [u8],
    framing: Framing,
    done: bool,
}

impl<'a> Iterator for ContentIter<'a> {
    type Item = Result<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.framing.known_len() {
            self.done = true;
            Some(get_sized(&mut self.slice))
        } else {
            let r = match is_terminator(&mut self.slice) {
                Err(e) => Some(Err(e)),
                Ok(true) => {
                    self.done = true;
                    None
                }
                Ok(false) => Some(get_sized(&mut self.slice)),
            };

            // Fuse parsing on error.
            if let Some(Err(_)) = &r {
                self.done = true;
            }
            r
        }
    }
}

/// Parser for tailer section.
#[derive(Clone, Copy)]
pub struct TailerParser<'a> {
    slice: &'a [u8],
    framing: Framing,
}

impl<'a> TailerParser<'a> {
    /// Return an iterator over each field line in tailer section.
    pub fn iter(&self) -> FieldIter {
        let truncated = self.slice.is_empty();
        FieldIter {
            slice: self.slice,
            framing: self.framing,
            done: truncated,
            len: None,
        }
    }

    /// Consume current parser, and return one for parse padding.
    pub fn next(self) -> Result<PaddingParser<'a>> {
        let mut iter = self.iter();
        let n = consumed!(iter)?;
        Ok(PaddingParser {
            slice: &self.slice[n..],
        })
    }
}

/// Parser for padding section.
#[derive(Clone, Copy)]
pub struct PaddingParser<'a> {
    slice: &'a [u8],
}

impl<'a> PaddingParser<'a> {
    /// Return the length of the padding.
    pub fn len(&self) -> usize {
        self.slice.len()
    }
}

/// Iterator over the fields, used in header, tailer, and
/// informational response control data.
pub struct FieldIter<'a> {
    slice: &'a [u8],
    framing: Framing,
    done: bool,
    len: Option<usize>,
}

impl<'a> Iterator for FieldIter<'a> {
    type Item = Result<(&'a [u8], &'a [u8])>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.framing.known_len() {
            let mut len = match self.len {
                None => {
                    match VarInt::parse(&mut self.slice).and_then(|n| {
                        let n = n.as_usize();
                        if self.slice.len() < n {
                            Err(Error::ShortBuf)
                        } else {
                            Ok(n)
                        }
                    }) {
                        Ok(n) => n,
                        Err(e) => {
                            self.done = true;
                            return Some(Err(e));
                        }
                    }
                }
                Some(v) => v,
            };

            if len == 0 {
                self.done = true;
                return None;
            }

            let n = self.slice.len();
            let r = parse_field(&mut self.slice);
            if r.is_err() {
                self.done = true;
            } else {
                len -= n - self.slice.len();
                self.len = Some(len);
            }
            Some(r)
        } else {
            let r = match is_terminator(&mut self.slice) {
                Err(e) => Some(Err(e)),
                Ok(true) => {
                    self.done = true;
                    None
                }
                Ok(false) => Some(parse_field(&mut self.slice)),
            };
            // Fuse parsing on error.
            if let Some(Err(_)) = &r {
                self.done = true;
            }
            r
        }
    }
}

fn get_sized<'a>(slice: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = VarInt::parse(slice)?.as_usize();
    if slice.remaining() < len {
        return Err(Error::ShortBuf);
    }
    let seg = &slice[..len];
    slice.advance(len);
    Ok(seg)
}

fn is_terminator(slice: &mut &[u8]) -> Result<bool> {
    // missing terminator
    if slice.is_empty() {
        return Err(Error::InvalidInput);
    }

    if slice[0] == CONTENT_TERMINATOR {
        slice.advance(1);
        Ok(true)
    } else {
        Ok(false)
    }
}

fn parse_field<'a>(slice: &mut &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
    Ok((get_sized(slice)?, get_sized(slice)?))
}

impl<'a> fmt::Display for Parser<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str_or_bytes = |f: &mut fmt::Formatter, prefix: &str, b: &[u8], suffix: &str| {
            if b.is_empty() {
                return Ok(());
            }

            match std::str::from_utf8(b) {
                Ok(s) => write!(f, "{}{}{}", prefix, s, suffix),
                _ => write!(f, "{}{:?}{}", prefix, b, suffix),
            }
        };

        let framing = self.framing().map_err(|_| fmt::Error)?;
        writeln!(f, "F {:?}", framing)?;

        let headers = if framing.is_request() {
            let req_ctrl = self.next_req().map_err(|_| fmt::Error)?;
            let ctrl = req_ctrl.get().map_err(|_| fmt::Error)?;
            str_or_bytes(f, "| method: ", ctrl.method, "\n")?;
            str_or_bytes(f, "| scheme: ", ctrl.scheme, "\n")?;
            str_or_bytes(f, "| authority: ", ctrl.authority, "\n")?;
            str_or_bytes(f, "| path: ", ctrl.path, "\n")?;
            req_ctrl.next().map_err(|_| fmt::Error)?
        } else {
            let res_ctrl = self.next_res().map_err(|_| fmt::Error)?;
            for item in res_ctrl.iter() {
                let (status, info) = item.map_err(|_| fmt::Error)?;
                writeln!(f, "| status: {}", status)?;
                if let Some(iter) = info {
                    for item in iter {
                        let (name, value) = item.map_err(|_| fmt::Error)?;
                        str_or_bytes(f, "|   ", name, ": ")?;
                        str_or_bytes(f, "", value, "\n")?;
                    }
                }
            }

            res_ctrl.next().map_err(|_| fmt::Error)?
        };

        for item in headers.iter() {
            let (name, value) = item.map_err(|_| fmt::Error)?;
            str_or_bytes(f, "H ", name, ": ")?;
            str_or_bytes(f, "", value, "\n")?;
        }

        let content = headers.next().map_err(|_| fmt::Error)?;
        for item in content.iter() {
            let chunk = item.map_err(|_| fmt::Error)?;
            str_or_bytes(f, "C ", chunk, "\n")?;
        }

        let tailers = content.next().map_err(|_| fmt::Error)?;
        for item in tailers.iter() {
            let (name, value) = item.map_err(|_| fmt::Error)?;
            str_or_bytes(f, "T ", name, ": ")?;
            str_or_bytes(f, "", value, "\n")?;
        }

        let padding = tailers.next().map_err(|_| fmt::Error)?;
        write!(f, "P: {}", padding.len())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_sized_segment() {
        let buf = hex!("06010203040506");
        let mut slice = &buf[..];
        let seg = get_sized(&mut slice).unwrap();
        assert_eq!(0, slice.len());
        assert_eq!(&buf[1..], seg);
    }

    #[test]
    fn parse_known_len_req() {
        let parser = Parser::new(EXAMPLE_KNOWN_LEN_REQ1);
        println!("{}", parser);
        assert_eq!(Ok(Framing::KnownLenReq), parser.framing());
        assert!(parser.next_res().is_err());
        let req_ctrl = parser.next_req().unwrap();
        let ctrl = req_ctrl.get().unwrap();
        assert_eq!(b"GET", ctrl.method);
        assert_eq!(b"https", ctrl.scheme);
        assert_eq!(b"example.com", ctrl.authority);
        assert_eq!(b"/", ctrl.path);
        let headers = req_ctrl.next().unwrap();
        // all the rest are truncated
        assert_eq!(None, headers.iter().next());
        let content = headers.next().unwrap();
        assert_eq!(None, content.iter().next());
        let tailers = content.next().unwrap();
        assert_eq!(None, tailers.iter().next());
        let padding = tailers.next().unwrap();
        assert_eq!(0, padding.len());

        let parser = Parser::new(EXAMPLE_KNOWN_LEN_REQ2);
        println!("{}", parser);
        assert_eq!(Ok(Framing::KnownLenReq), parser.framing());
        let req_ctrl = parser.next_req().unwrap();
        let ctrl = req_ctrl.get().unwrap();
        assert_eq!(b"GET", ctrl.method);
        assert_eq!(b"https", ctrl.scheme);
        assert_eq!(b"", ctrl.authority);
        assert_eq!(b"/hello.txt", ctrl.path);

        let headers = req_ctrl.next().unwrap();
        let mut header_iter = headers.iter();
        assert_eq!(
            (
                "user-agent",
                "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"
            ),
            unwrap_fieldline(header_iter.next())
        );
        assert_eq!(
            ("host", "www.example.com"),
            unwrap_fieldline(header_iter.next())
        );
        assert_eq!(
            ("accept-language", "en, mi"),
            unwrap_fieldline(header_iter.next())
        );
        assert_eq!(None, header_iter.next());

        let content = headers.next().unwrap();
        assert_eq!(Some(Ok(&[][..])), content.iter().next());
        let tailers = content.next().unwrap();
        assert_eq!(None, tailers.iter().next());
        let padding = tailers.next().unwrap();
        assert_eq!(0, padding.len());
    }

    #[test]
    fn parse_ind_len_req() {
        let parser = Parser::new(EXAMPLE_IND_LEN_REQ1);
        println!("{}", parser);
        assert_eq!(Ok(Framing::IndLenReq), parser.framing());
        let req_ctrl = parser.next_req().unwrap();
        let ctrl = req_ctrl.get().unwrap();
        assert_eq!(b"GET", ctrl.method);
        assert_eq!(b"https", ctrl.scheme);
        assert_eq!(b"", ctrl.authority);
        assert_eq!(b"/hello.txt", ctrl.path);
        let headers = req_ctrl.next().unwrap();
        let mut header_iter = headers.iter();
        assert_eq!(
            (
                "user-agent",
                "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"
            ),
            unwrap_fieldline(header_iter.next())
        );
        assert_eq!(
            ("host", "www.example.com"),
            unwrap_fieldline(header_iter.next())
        );
        assert_eq!(
            ("accept-language", "en, mi"),
            unwrap_fieldline(header_iter.next())
        );
        assert_eq!(None, header_iter.next());

        let content = headers.next().unwrap();
        assert_eq!(None, content.iter().next());
        let tailers = content.next().unwrap();
        assert_eq!(None, tailers.iter().next());
        let padding = tailers.next().unwrap();
        assert_eq!(10, padding.len());

        // above request with truncation
        let parser = Parser::new(EXAMPLE_IND_LEN_REQ2);
        let req_ctrl = parser.next_req().unwrap();
        let headers = req_ctrl.next().unwrap();
        let content = headers.next().unwrap();
        assert_eq!(None, content.iter().next());
        let tailers = content.next().unwrap();
        assert_eq!(None, tailers.iter().next());
        let padding = tailers.next().unwrap();
        assert_eq!(0, padding.len());
    }

    #[test]
    fn parse_known_len_res() {
        let parser = Parser::new(EXAMPLE_KNOWN_LEN_RES1);
        println!("{}", parser);
        assert_eq!(Ok(Framing::KnownLenRes), parser.framing());
        let res_ctrl = parser.next_res().unwrap();

        let mut iter = res_ctrl.iter();
        let (status, info) = iter.next().unwrap().unwrap();
        assert_eq!(200, status);
        assert!(info.is_none());

        let headers = res_ctrl.next().unwrap();
        let mut iter = headers.iter();
        assert_eq!(None, iter.next());

        let content = headers.next().unwrap();
        let mut iter = content.iter();
        assert_eq!(
            &b"This content contains CRLF.\r\n"[..],
            iter.next().unwrap().unwrap()
        );

        let tailers = content.next().unwrap();
        let mut iter = tailers.iter();
        assert_eq!(("trailer", "text"), unwrap_fieldline(iter.next()));
        let padding = tailers.next().unwrap();
        assert_eq!(0, padding.len());
    }

    #[test]
    fn parse_ind_len_res() {
        let parser = Parser::new(EXAMPLE_IND_LEN_RES1);
        println!("{}", parser);
        assert_eq!(Ok(Framing::IndLenRes), parser.framing());

        let res_ctrl = parser.next_res().unwrap();
        let mut iter = res_ctrl.iter();
        let (status, info_iter) = iter.next().unwrap().unwrap();
        assert_eq!(102, status);
        let mut info_iter = info_iter.unwrap();
        assert_eq!(
            ("running", r#""sleep 15""#),
            unwrap_fieldline(info_iter.next())
        );
        assert_eq!(None, info_iter.next());

        let (status, info_iter) = iter.next().unwrap().unwrap();
        assert_eq!(103, status);
        let mut info_iter = info_iter.unwrap();
        assert_eq!(
            ("link", r#"</style.css>; rel=preload; as=style"#),
            unwrap_fieldline(info_iter.next())
        );
        assert_eq!(
            ("link", r#"</script.js>; rel=preload; as=script"#),
            unwrap_fieldline(info_iter.next())
        );
        assert_eq!(None, info_iter.next());
        let (status, info_iter) = iter.next().unwrap().unwrap();
        assert_eq!(200, status);
        assert!(info_iter.is_none());
        assert!(iter.next().is_none());

        let headers = res_ctrl.next().unwrap();
        let mut iter = headers.iter();
        assert_eq!(
            ("date", "Mon, 27 Jul 2009 12:28:53 GMT"),
            unwrap_fieldline(iter.next())
        );
        assert_eq!(("server", "Apache"), unwrap_fieldline(iter.next()));
        assert_eq!(
            ("last-modified", "Wed, 22 Jul 2009 19:15:56 GMT"),
            unwrap_fieldline(iter.next())
        );
        assert_eq!(
            ("etag", r#""34aa387-d-1568eb00""#),
            unwrap_fieldline(iter.next())
        );
        assert_eq!(("accept-ranges", "bytes"), unwrap_fieldline(iter.next()));
        assert_eq!(("content-length", "51"), unwrap_fieldline(iter.next()));
        assert_eq!(("vary", "Accept-Encoding"), unwrap_fieldline(iter.next()));
        assert_eq!(
            ("content-type", "text/plain"),
            unwrap_fieldline(iter.next())
        );
        assert!(iter.next().is_none());

        let content = headers.next().unwrap();
        let mut iter = content.iter();
        assert_eq!(
            &b"Hello World! My content includes a trailing CRLF.\r\n"[..],
            iter.next().unwrap().unwrap()
        );
        assert!(iter.next().is_none());

        let tailers = content.next().unwrap();
        let mut iter = tailers.iter();
        assert!(iter.next().is_none());

        let padding = tailers.next().unwrap();
        assert_eq!(0, padding.len());
    }
}
