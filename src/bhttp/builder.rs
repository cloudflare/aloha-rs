use bytes::BufMut;

use super::*;

/// Entrypoint to build a bHTTP message.
pub struct Builder<B> {
    buf: B,
    framing: Framing,
}

impl<B: BufMut> Builder<B> {
    /// Create a new builder.
    pub fn new(buf: B, framing: Framing) -> Self {
        Self { buf, framing }
    }

    /// Push request control data.
    pub fn push_ctrl(
        mut self,
        mut method: &[u8],
        mut scheme: &[u8],
        mut authority: &[u8],
        mut path: &[u8],
    ) -> Result<HeaderBuilder<B>> {
        if !self.framing.is_request() {
            return Err(Error::UnexpectedFraming);
        }

        if !self.buf.has_remaining_mut() {
            return Err(Error::ShortBuf);
        }
        self.buf.put_u8(self.framing as u8);

        compose_len_bytes(&mut self.buf, &mut method)?;
        compose_len_bytes(&mut self.buf, &mut scheme)?;
        compose_len_bytes(&mut self.buf, &mut authority)?;
        compose_len_bytes(&mut self.buf, &mut path)?;

        Ok(HeaderBuilder {
            buf: self.buf,
            framing: self.framing,
            appending: false,
        })
    }

    /// Push informational/final response contral data.
    pub fn push_status(mut self, status: usize) -> Result<InfoBuilder<B>> {
        if self.framing.is_request() {
            return Err(Error::UnexpectedFraming);
        }

        if !self.buf.has_remaining_mut() {
            return Err(Error::ShortBuf);
        }
        self.buf.put_u8(self.framing as u8);

        VarInt::try_from(status)?.compose(&mut self.buf)?;

        Ok(InfoBuilder {
            buf: self.buf,
            framing: self.framing,
            is_final: is_final_ctrl(status),
            appending: false,
        })
    }
}

/// Build response informational/final control data.
pub struct RCtrlBuilder<B> {
    buf: B,
    framing: Framing,
}

impl<B: BufMut> RCtrlBuilder<B> {
    /// Push informational/final response contral data.
    pub fn push_status(mut self, status: usize) -> Result<InfoBuilder<B>> {
        VarInt::try_from(status)?.compose(&mut self.buf)?;
        Ok(InfoBuilder {
            buf: self.buf,
            framing: self.framing,
            is_final: is_final_ctrl(status),
            appending: false,
        })
    }
}

/// Build informational response fields.
pub struct InfoBuilder<B> {
    buf: B,
    framing: Framing,
    is_final: bool,
    appending: bool,
}

impl<B: BufMut> InfoBuilder<B> {
    /// Push all the informational fields.
    pub fn push_fields(mut self, fields: &[(&[u8], &[u8])]) -> Result<RCtrlBuilder<B>> {
        if self.is_final {
            return Err(Error::UnexpectedBuildState);
        }

        push_fields(&mut self.buf, self.framing, fields)?;
        Ok(RCtrlBuilder {
            buf: self.buf,
            framing: self.framing,
        })
    }

    /// Append a single field line in indeterminate length mode.
    pub fn append_field(mut self, field: (&[u8], &[u8])) -> Result<Self> {
        if self.framing.known_len() {
            return Err(Error::UnexpectedFraming);
        }

        if self.is_final {
            return Err(Error::UnexpectedBuildState);
        }

        let (mut name, mut value) = field;
        if name.is_empty() {
            return Err(Error::InvalidInput);
        }
        compose_len_bytes(&mut self.buf, &mut name)?;
        compose_len_bytes(&mut self.buf, &mut value)?;
        self.appending = true;
        Ok(self)
    }

    /// Finish appending field line.
    pub fn done(mut self) -> Result<RCtrlBuilder<B>> {
        if self.framing.known_len() {
            return Err(Error::UnexpectedFraming);
        }

        if self.is_final || !self.appending {
            return Err(Error::UnexpectedBuildState);
        }

        if !self.buf.has_remaining_mut() {
            return Err(Error::ShortBuf);
        }
        self.buf.put_u8(CONTENT_TERMINATOR);

        Ok(RCtrlBuilder {
            buf: self.buf,
            framing: self.framing,
        })
    }

    /// Move to next builder in chain.
    pub fn next(self) -> Result<HeaderBuilder<B>> {
        if !self.is_final {
            return Err(Error::UnexpectedBuildState);
        }

        Ok(HeaderBuilder {
            buf: self.buf,
            framing: self.framing,
            appending: false,
        })
    }
}

/// Build headers.
pub struct HeaderBuilder<B> {
    buf: B,
    framing: Framing,
    appending: bool,
}

impl<B: BufMut> HeaderBuilder<B> {
    /// Push all the headers.
    pub fn push_headers(mut self, fields: &[(&[u8], &[u8])]) -> Result<ContentBuilder<B>> {
        push_fields(&mut self.buf, self.framing, fields)?;
        Ok(ContentBuilder {
            buf: self.buf,
            framing: self.framing,
            appending: false,
        })
    }

    /// Append a single header in indeterminate length mode.
    pub fn append_header(mut self, field: (&[u8], &[u8])) -> Result<Self> {
        if self.framing.known_len() {
            return Err(Error::UnexpectedFraming);
        }

        let (mut name, mut value) = field;
        if name.is_empty() {
            return Err(Error::InvalidInput);
        }
        compose_len_bytes(&mut self.buf, &mut name)?;
        compose_len_bytes(&mut self.buf, &mut value)?;
        self.appending = true;
        Ok(self)
    }

    /// Move to next builder in chain.
    pub fn next(mut self) -> Result<ContentBuilder<B>> {
        if !self.appending {
            return Err(Error::UnexpectedBuildState);
        }

        if !self.buf.has_remaining_mut() {
            return Err(Error::ShortBuf);
        }
        self.buf.put_u8(CONTENT_TERMINATOR);
        Ok(ContentBuilder {
            buf: self.buf,
            framing: self.framing,
            appending: false,
        })
    }
}

/// Build content.
pub struct ContentBuilder<B> {
    buf: B,
    framing: Framing,
    appending: bool,
}

impl<B: BufMut> ContentBuilder<B> {
    /// Push content at once.
    pub fn push_content(mut self, mut content: &[u8]) -> Result<TailerBuilder<B>> {
        let empty = content.is_empty();
        compose_len_bytes(&mut self.buf, &mut content)?;

        // Content has already been terminated if empty.
        if !self.framing.known_len() && !empty {
            if !self.buf.has_remaining_mut() {
                return Err(Error::ShortBuf);
            }
            self.buf.put_u8(CONTENT_TERMINATOR);
        }

        Ok(TailerBuilder {
            buf: self.buf,
            framing: self.framing,
            appending: false,
        })
    }

    /// Append a content chunk in indeterminate length mode.
    pub fn append_chunk(mut self, mut chunk: &[u8]) -> Result<Self> {
        if chunk.is_empty() {
            return Err(Error::InvalidInput);
        }

        compose_len_bytes(&mut self.buf, &mut chunk)?;
        self.appending = true;
        Ok(self)
    }

    /// Move to next builder in chain.
    pub fn next(mut self) -> Result<TailerBuilder<B>> {
        if !self.buf.has_remaining_mut() {
            return Err(Error::ShortBuf);
        }
        self.buf.put_u8(CONTENT_TERMINATOR);

        Ok(TailerBuilder {
            buf: self.buf,
            framing: self.framing,
            appending: false,
        })
    }
}

/// Build tailers.
pub struct TailerBuilder<B> {
    buf: B,
    framing: Framing,
    appending: bool,
}

impl<B: BufMut> TailerBuilder<B> {
    /// Push all tailers at once.
    pub fn push_tailers(mut self, fields: &[(&[u8], &[u8])]) -> Result<PaddingBuilder<B>> {
        push_fields(&mut self.buf, self.framing, fields)?;
        Ok(PaddingBuilder { buf: self.buf })
    }

    /// Append a single tailer in indeterminate length mode.
    pub fn append_tailer(mut self, field: (&[u8], &[u8])) -> Result<Self> {
        if self.framing.known_len() {
            return Err(Error::UnexpectedFraming);
        }

        let (mut name, mut value) = field;
        if name.is_empty() {
            return Err(Error::InvalidInput);
        }
        compose_len_bytes(&mut self.buf, &mut name)?;
        compose_len_bytes(&mut self.buf, &mut value)?;
        self.appending = true;
        Ok(self)
    }

    /// Move to next builder in chain.
    pub fn next(mut self) -> Result<PaddingBuilder<B>> {
        if !self.appending {
            return Err(Error::UnexpectedBuildState);
        }

        if !self.buf.has_remaining_mut() {
            return Err(Error::ShortBuf);
        }
        self.buf.put_u8(CONTENT_TERMINATOR);
        Ok(PaddingBuilder { buf: self.buf })
    }
}

/// Build padding.
pub struct PaddingBuilder<B> {
    buf: B,
}

impl<B: BufMut> PaddingBuilder<B> {
    /// Push n bytes of padding.
    pub fn push_padding(mut self, n: usize) -> Result<()> {
        if self.buf.remaining_mut() < n {
            return Err(Error::ShortBuf);
        }
        self.buf.put_bytes(CONTENT_TERMINATOR, n);
        Ok(())
    }
}

fn push_fields<B: BufMut>(buf: &mut B, framing: Framing, fields: &[(&[u8], &[u8])]) -> Result<()> {
    if framing.known_len() {
        push_fields_with_len(buf, fields)
    } else {
        push_fields_no_len(buf, fields)
    }
}

fn push_fields_with_len<B: BufMut>(buf: &mut B, fields: &[(&[u8], &[u8])]) -> Result<()> {
    let mut len = 0;
    for (name, value) in fields.iter() {
        len += VarInt::try_from(name.len())?.size();
        len += name.len();
        len += VarInt::try_from(value.len())?.size();
        len += value.len();
    }

    let n = VarInt::try_from(len)?;
    if buf.remaining_mut() < n.size() + len {
        return Err(Error::ShortBuf);
    }

    n.compose(buf)?;

    for (mut name, mut value) in fields.iter() {
        compose_len_bytes(buf, &mut name)?;
        compose_len_bytes(buf, &mut value)?;
    }

    Ok(())
}

fn push_fields_no_len<B: BufMut>(buf: &mut B, fields: &[(&[u8], &[u8])]) -> Result<()> {
    for (mut name, mut value) in fields.iter() {
        if name.is_empty() {
            return Err(Error::InvalidInput);
        }
        compose_len_bytes(buf, &mut name)?;
        compose_len_bytes(buf, &mut value)?;
    }

    if !buf.has_remaining_mut() {
        return Err(Error::ShortBuf);
    }
    buf.put_u8(CONTENT_TERMINATOR);

    Ok(())
}

// If data is empty, 1 byte of 0 will be pushed.
fn compose_len_bytes<B: BufMut, T: Buf>(buf: &mut B, data: &mut T) -> Result<()> {
    let len = data.remaining();
    let n = VarInt::try_from(len)?;

    if buf.remaining_mut() < n.size() + len {
        return Err(Error::ShortBuf);
    }

    n.compose(buf)?;
    buf.put(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn build_known_len_req() {
        let mut buf = Vec::new();
        Builder::new(&mut buf, Framing::KnownLenReq)
            .push_ctrl(b"GET", b"https", b"", b"/hello.txt")
            .unwrap()
            .push_headers(&[
                (
                    &b"user-agent"[..],
                    &b"curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"[..],
                ),
                (&b"host"[..], &b"www.example.com"[..]),
                (&b"accept-language"[..], &b"en, mi"[..]),
            ])
            .unwrap()
            .push_content(&[])
            .unwrap()
            .push_tailers(&[])
            .unwrap();
        assert_eq!(EXAMPLE_KNOWN_LEN_REQ2, buf);
    }

    #[test]
    fn build_ind_len_req() {
        let mut buf = Vec::new();
        Builder::new(&mut buf, Framing::IndLenReq)
            .push_ctrl(b"GET", b"https", b"", b"/hello.txt")
            .unwrap()
            .push_headers(&[
                (
                    &b"user-agent"[..],
                    &b"curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"[..],
                ),
                (&b"host"[..], &b"www.example.com"[..]),
                (&b"accept-language"[..], &b"en, mi"[..]),
            ])
            .unwrap()
            .push_content(&[])
            .unwrap()
            .push_tailers(&[])
            .unwrap()
            .push_padding(10)
            .unwrap();
        assert_eq!(EXAMPLE_IND_LEN_REQ1, buf);
    }

    #[test]
    fn build_known_len_res() {
        let mut buf = Vec::new();
        Builder::new(&mut buf, Framing::KnownLenRes)
            .push_status(200)
            .unwrap()
            .next()
            .unwrap()
            .push_headers(&[])
            .unwrap()
            .push_content("This content contains CRLF.\r\n".as_bytes())
            .unwrap()
            .push_tailers(&[("trailer".as_bytes(), "text".as_bytes())])
            .unwrap();
        assert_eq!(EXAMPLE_KNOWN_LEN_RES1, buf);
    }

    #[test]
    fn build_ind_len_res() {
        let mut buf = Vec::new();
        Builder::new(&mut buf, Framing::IndLenRes)
            .push_status(102)
            .unwrap()
            .push_fields(&[("running".as_bytes(), r#""sleep 15""#.as_bytes())])
            .unwrap()
            .push_status(103)
            .unwrap()
            .push_fields(&[
                (
                    "link".as_bytes(),
                    r#"</style.css>; rel=preload; as=style"#.as_bytes(),
                ),
                (
                    "link".as_bytes(),
                    r#"</script.js>; rel=preload; as=script"#.as_bytes(),
                ),
            ])
            .unwrap()
            .push_status(200)
            .unwrap()
            .next()
            .unwrap()
            .push_headers(&[
                (
                    "date".as_bytes(),
                    r#"Mon, 27 Jul 2009 12:28:53 GMT"#.as_bytes(),
                ),
                ("server".as_bytes(), "Apache".as_bytes()),
                (
                    "last-modified".as_bytes(),
                    "Wed, 22 Jul 2009 19:15:56 GMT".as_bytes(),
                ),
                ("etag".as_bytes(), r#""34aa387-d-1568eb00""#.as_bytes()),
                ("accept-ranges".as_bytes(), "bytes".as_bytes()),
                ("content-length".as_bytes(), "51".as_bytes()),
                ("vary".as_bytes(), "Accept-Encoding".as_bytes()),
                ("content-type".as_bytes(), "text/plain".as_bytes()),
            ])
            .unwrap()
            .push_content("Hello World! My content includes a trailing CRLF.\r\n".as_bytes())
            .unwrap()
            .push_tailers(&[])
            .unwrap();

        assert_eq!(EXAMPLE_IND_LEN_RES1, &buf);
    }
}
