use aead::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};
use bytes::{BufMut, Bytes, BytesMut};
use generic_array::GenericArray;
use hkdf::hmac::{digest::OutputSizeUser, Hmac};
use hkdf::{Hkdf, HmacImpl};
use hpke::aead::{Aead, AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf};
use hpke::kem::Kem;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand::Rng;
use rand::{CryptoRng, RngCore};

use super::*;

/// Macro to dispatch the generic functions based on the algorithm id
/// in the header.
macro_rules! dispatch {
    ($(<$pre:ident>)? $f:ident <$($kem:ident)? $(,$g:ident)* >($hdr:ident $(,$arg:ident)* $(,)?)) => {
        match $hdr.kdf_id {
            HkdfSha256::KDF_ID => dispatch!(inner, $(<$pre>)?$f::<$(|$kem,)? HkdfSha256 $(,$g)*>($hdr $(,$arg)*)),
            HkdfSha384::KDF_ID => dispatch!(inner, $(<$pre>)?$f::<$(|$kem,)? HkdfSha384 $(,$g)*>($hdr $(,$arg)*)),
            HkdfSha512::KDF_ID => dispatch!(inner, $(<$pre>)?$f::<$(|$kem,)? HkdfSha512 $(,$g)*>($hdr $(,$arg)*)),
            _ => Err(Error::UnsupportedKdf),
        }
    };

    (inner, $(<$pre:ident>)? $f:ident::<$(|$kem:ident,)? $kdf:ty $(,$g:ident)* >($hdr:ident $(,$arg:ident)* $(,)?)) => {
        match $hdr.aead_id {
            AesGcm128::AEAD_ID => $($pre::)?$f::<$($kem,)? $kdf, AesGcm128 $(,$g)*>($hdr $(,$arg)*),
            AesGcm256::AEAD_ID => $($pre::)?$f::<$($kem,)? $kdf, AesGcm256 $(,$g)*>($hdr $(,$arg)*),
            ChaCha20Poly1305::AEAD_ID => $($pre::)?$f::<$($kem,)? $kdf, ChaCha20Poly1305 $(,$g)*>($hdr $(,$arg)*),
            _ => Err(Error::UnsupportedAead),
        }
    };
}

pub(crate) fn encrypt_req<KEM: Kem, R: RngCore + CryptoRng>(
    hdr: Header,
    pubkey: &<KEM as Kem>::PublicKey,
    req: &[u8],
    rng: &mut R,
) -> Result<(BytesMut, Ctx)> {
    dispatch!(encrypt_req_with < KEM, R > (hdr, pubkey, req, rng))
}

fn encrypt_req_with<KEM: Kem, KDF: Kdf, AEAD: Aead, R: RngCore + CryptoRng>(
    hdr: Header,
    pubkey: &<KEM as Kem>::PublicKey,
    req: &[u8],
    rng: &mut R,
) -> Result<(BytesMut, Ctx)> {
    // create info
    let mut info = [0u8; LABEL_REQ.len() + 1 + Header::SIZE];
    compose_info::<KEM, KDF, AEAD, _>(hdr.cid, LABEL_REQ.as_bytes(), &mut &mut info[..])?;

    let (enc_key, mut ctx) =
        hpke::setup_sender::<AEAD, KDF, KEM, _>(&OpModeS::Base, pubkey, &info, rng)?;
    let enc_key_bytes = enc_key.to_bytes();

    let mut buf = BytesMut::with_capacity(
        Header::SIZE + enc_key_bytes.len() + req.len() + AeadTag::<AEAD>::size(),
    );

    compose_header::<KEM, KDF, AEAD, _>(hdr.cid, &mut buf)?;
    buf.put(enc_key_bytes.as_ref());

    // push req into buffer for inplace seal
    let start = buf.len();
    buf.put(req);
    let end = buf.len();

    let tag = ctx.seal_in_place_detached(&mut buf.as_mut()[start..end], &[])?;

    buf.put(tag.to_bytes().as_ref());

    // let secret: GenericArray<u8, <<AEAD as Aead>::AeadImpl as KeySizeUser>::KeySize> =
    //     Default::default();
    let mut secret = vec![0; aead_key_size::<AEAD>()];
    ctx.export(LABEL_RES.as_bytes(), &mut secret)?;

    let out_ctx = Ctx {
        hdr,
        secret: secret.into(),
        encapped_key: Bytes::copy_from_slice(&enc_key_bytes),
    };
    Ok((buf, out_ctx))
}

pub(crate) fn decrypt_req_in_place<KEM: Kem, B: InPlaceMut>(
    hdr: Header,
    enc_req: B,
    priv_key: &<KEM as Kem>::PrivateKey,
) -> Result<(B, Ctx)> {
    dispatch!(<B> decrypt_req_in_place <KEM> (hdr, enc_req, priv_key))
}

/// Trait to support in place operations over a mutable buffer. The
/// method is an associated function because it can benefit from the
/// internal macros, same reason for the unused header parameter in
/// response decryption.
pub trait InPlaceMut: Sized {
    fn decrypt_req_in_place<KEM, KDF, AEAD>(
        hdr: Header,
        buf: Self,
        priv_key: &<KEM as Kem>::PrivateKey,
    ) -> Result<(Self, Ctx)>
    where
        KEM: Kem,
        KDF: Kdf,
        AEAD: Aead;

    fn decrypt_res_in_place<KDF, AEAD>(
        _hdr: Header,
        buf: Self,
        enc_key: &[u8],
        secret: &[u8],
    ) -> Result<Self>
    where
        KDF: Kdf,
        AEAD: Aead;
}

impl InPlaceMut for BytesMut {
    fn decrypt_req_in_place<KEM, KDF, AEAD>(
        hdr: Header,
        mut buf: BytesMut,
        priv_key: &<KEM as Kem>::PrivateKey,
    ) -> Result<(BytesMut, Ctx)>
    where
        KEM: Kem,
        KDF: Kdf,
        AEAD: Aead,
    {
        // buf: [hdr encapped_key encrypted_req tag]

        let enc_key_len = <KEM as Kem>::EncappedKey::size();
        let tag_len = AeadTag::<AEAD>::size();
        if buf.len() < Header::SIZE + enc_key_len + tag_len {
            return Err(Error::InvalidInput);
        }

        let mut out_ctx = Ctx {
            hdr,
            ..Default::default()
        };

        let _ = buf.split_to(Header::SIZE);
        let enc_key_bytes = buf.split_to(enc_key_len);
        let enc_key = <KEM as Kem>::EncappedKey::from_bytes(&enc_key_bytes)?;
        out_ctx.encapped_key = enc_key_bytes.freeze();
        let tag_bytes = buf.split_off(buf.len() - tag_len);
        let tag = AeadTag::from_bytes(&tag_bytes)?;

        let mut info = [0u8; LABEL_REQ.len() + 1 + Header::SIZE];
        compose_info::<KEM, KDF, AEAD, _>(hdr.cid, LABEL_REQ.as_bytes(), &mut &mut info[..])?;

        let mut recv_ctx =
            hpke::setup_receiver::<AEAD, KDF, KEM>(&OpModeR::Base, priv_key, &enc_key, &info)?;

        recv_ctx.open_in_place_detached(&mut buf, &[], &tag)?;

        let mut secret = vec![0; aead_key_size::<AEAD>()];
        recv_ctx.export(LABEL_RES.as_bytes(), &mut secret)?;
        out_ctx.secret = secret.into();

        Ok((buf, out_ctx))
    }

    fn decrypt_res_in_place<KDF, AEAD>(
        _hdr: Header,
        mut buf: BytesMut,
        enc_key: &[u8],
        secret: &[u8],
    ) -> Result<BytesMut>
    where
        KDF: Kdf,
        AEAD: Aead,
    {
        // buf contains [res_nonce res tag]
        let res_nonce_size = res_nonce_size::<AEAD>();
        let tag_size = AeadTag::<AEAD>::size();
        if buf.len() < res_nonce_size + tag_size {
            return Err(Error::InvalidInput);
        }

        let res_nonce = buf.split_to(res_nonce_size);
        let tag = buf.split_off(buf.len() - tag_size);

        let mut salt = enc_key.to_vec();
        salt.extend_from_slice(&res_nonce);
        let (key, nonce) = match <KDF as Kdf>::KDF_ID {
            HkdfSha256::KDF_ID => {
                extract_and_expand::<AEAD, <HkdfSha256 as Kdf>::HashImpl, Hmac<_>>(&salt, secret)
                    .map(|(_prk, key, nonce)| (key, nonce))
            }
            HkdfSha384::KDF_ID => {
                extract_and_expand::<AEAD, <HkdfSha384 as Kdf>::HashImpl, Hmac<_>>(&salt, secret)
                    .map(|(_prk, key, nonce)| (key, nonce))
            }
            HkdfSha512::KDF_ID => {
                extract_and_expand::<AEAD, <HkdfSha512 as Kdf>::HashImpl, Hmac<_>>(&salt, secret)
                    .map(|(_prk, key, nonce)| (key, nonce))
            }
            _ => return Err(Error::UnsupportedKdf),
        }?;

        let cipher = <AEAD as Aead>::AeadImpl::new(&key);

        cipher
            .decrypt_in_place_detached(&nonce, &[], &mut buf, GenericArray::from_slice(&tag))
            .map_err(|_| Error::AeadError)?;
        Ok(buf)
    }
}

impl<'a> InPlaceMut for &'a mut [u8] {
    fn decrypt_req_in_place<KEM, KDF, AEAD>(
        hdr: Header,
        buf: &'a mut [u8],
        priv_key: &<KEM as Kem>::PrivateKey,
    ) -> Result<(&'a mut [u8], Ctx)>
    where
        KEM: Kem,
        KDF: Kdf,
        AEAD: Aead,
    {
        // buf: [hdr encapped_key encrypted_req tag]

        let enc_key_len = <KEM as Kem>::EncappedKey::size();
        let tag_len = AeadTag::<AEAD>::size();
        if buf.len() < Header::SIZE + enc_key_len + tag_len {
            return Err(Error::InvalidInput);
        }

        let mut out_ctx = Ctx {
            hdr,
            ..Default::default()
        };

        let (_, buf) = buf.split_at_mut(Header::SIZE);
        let (enc_key_bytes, buf) = buf.split_at_mut(enc_key_len);
        let enc_key = <KEM as Kem>::EncappedKey::from_bytes(enc_key_bytes)?;
        out_ctx.encapped_key = Bytes::copy_from_slice(enc_key_bytes);
        let (buf, tag_bytes) = buf.split_at_mut(buf.len() - tag_len);
        let tag = AeadTag::from_bytes(tag_bytes)?;

        let mut info = [0u8; LABEL_REQ.len() + 1 + Header::SIZE];
        compose_info::<KEM, KDF, AEAD, _>(hdr.cid, LABEL_REQ.as_bytes(), &mut &mut info[..])?;

        let mut recv_ctx =
            hpke::setup_receiver::<AEAD, KDF, KEM>(&OpModeR::Base, priv_key, &enc_key, &info)?;

        recv_ctx.open_in_place_detached(buf, &[], &tag)?;

        let mut secret = vec![0; aead_key_size::<AEAD>()];
        recv_ctx.export(LABEL_RES.as_bytes(), &mut secret)?;
        out_ctx.secret = secret.into();

        Ok((buf, out_ctx))
    }

    fn decrypt_res_in_place<KDF, AEAD>(
        _hdr: Header,
        buf: &'a mut [u8],
        enc_key: &[u8],
        secret: &[u8],
    ) -> Result<&'a mut [u8]>
    where
        KDF: Kdf,
        AEAD: Aead,
    {
        // buf contains [res_nonce res tag]
        let res_nonce_size = res_nonce_size::<AEAD>();
        let tag_size = AeadTag::<AEAD>::size();
        if buf.len() < res_nonce_size + tag_size {
            return Err(Error::InvalidInput);
        }

        let (res_nonce, buf) = buf.split_at_mut(res_nonce_size);
        let (buf, tag) = buf.split_at_mut(buf.len() - tag_size);

        let mut salt = enc_key.to_vec();
        salt.extend_from_slice(res_nonce);
        let (key, nonce) = match <KDF as Kdf>::KDF_ID {
            HkdfSha256::KDF_ID => {
                extract_and_expand::<AEAD, <HkdfSha256 as Kdf>::HashImpl, Hmac<_>>(&salt, secret)
                    .map(|(_prk, key, nonce)| (key, nonce))
            }
            HkdfSha384::KDF_ID => {
                extract_and_expand::<AEAD, <HkdfSha384 as Kdf>::HashImpl, Hmac<_>>(&salt, secret)
                    .map(|(_prk, key, nonce)| (key, nonce))
            }
            HkdfSha512::KDF_ID => {
                extract_and_expand::<AEAD, <HkdfSha512 as Kdf>::HashImpl, Hmac<_>>(&salt, secret)
                    .map(|(_prk, key, nonce)| (key, nonce))
            }
            _ => return Err(Error::UnsupportedKdf),
        }?;

        let cipher = <AEAD as Aead>::AeadImpl::new(&key);

        cipher
            .decrypt_in_place_detached(&nonce, &[], buf, GenericArray::from_slice(tag))
            .map_err(|_| Error::AeadError)?;
        Ok(buf)
    }
}

pub(crate) fn encrypt_res<R: RngCore + CryptoRng>(
    hdr: Header,
    res: &[u8],
    enc_key: &[u8],
    secret: &[u8],
    rng: &mut R,
) -> Result<BytesMut> {
    dispatch!(encrypt_res_with_header <, R> (hdr, res, enc_key, secret, rng))
}

fn encrypt_res_with_header<KDF: Kdf, AEAD: Aead, R: RngCore + CryptoRng>(
    _hdr: Header,
    res: &[u8],
    enc_key: &[u8],
    secret: &[u8],
    rng: &mut R,
) -> Result<BytesMut> {
    encrypt_res_with::<KDF, AEAD, R>(res, enc_key, secret, rng)
}

fn encrypt_res_with<KDF: Kdf, AEAD: Aead, R: RngCore + CryptoRng>(
    res: &[u8],
    enc_key: &[u8],
    secret: &[u8],
    rng: &mut R,
) -> Result<BytesMut> {
    let res_nonce_len = res_nonce_size::<AEAD>();

    // buf will contain [enc_key res_nonce res tag]
    let mut buf = BytesMut::with_capacity(
        enc_key.len() + res_nonce_len + res.len() + AeadTag::<AEAD>::size(),
    );
    buf.put(enc_key);
    // reserv for nonce, and fill with random data
    buf.put_bytes(0, res_nonce_len);
    rng.fill(&mut buf[enc_key.len()..]);

    // buf contains salt(enc_key + res_nonce) now

    let (key, nonce) = match <KDF as Kdf>::KDF_ID {
        HkdfSha256::KDF_ID => {
            extract_and_expand::<AEAD, <HkdfSha256 as Kdf>::HashImpl, Hmac<_>>(&buf, secret)
                .map(|(_prk, key, nonce)| (key, nonce))
        }
        HkdfSha384::KDF_ID => {
            extract_and_expand::<AEAD, <HkdfSha384 as Kdf>::HashImpl, Hmac<_>>(&buf, secret)
                .map(|(_prk, key, nonce)| (key, nonce))
        }
        HkdfSha512::KDF_ID => {
            extract_and_expand::<AEAD, <HkdfSha512 as Kdf>::HashImpl, Hmac<_>>(&buf, secret)
                .map(|(_prk, key, nonce)| (key, nonce))
        }
        _ => return Err(Error::UnsupportedKdf),
    }?;

    let cipher = <AEAD as Aead>::AeadImpl::new(&key);
    buf.put(res);

    let tag = cipher
        .encrypt_in_place_detached(&nonce, &[], &mut buf[enc_key.len() + res_nonce_len..])
        .map_err(|_| Error::AeadError)?;

    buf.put(tag.as_slice());
    let _enc_key = buf.split_to(enc_key.len());

    Ok(buf)
}

pub(crate) fn decrypt_res_in_place<B: InPlaceMut>(
    hdr: Header,
    enc_res: B,
    enc_key: &[u8],
    secret: &[u8],
) -> Result<B> {
    dispatch!(<B> decrypt_res_in_place <> (hdr, enc_res, enc_key, secret))
}

type EEOut<H, A> = (
    GenericArray<u8, <H as OutputSizeUser>::OutputSize>,
    GenericArray<u8, <<A as Aead>::AeadImpl as KeySizeUser>::KeySize>,
    GenericArray<u8, <<A as Aead>::AeadImpl as AeadCore>::NonceSize>,
);

fn extract_and_expand<A, H, I>(salt: &[u8], secret: &[u8]) -> Result<EEOut<H, A>>
where
    A: Aead,
    H: OutputSizeUser,
    I: HmacImpl<H>,
{
    let (prk, hk) = Hkdf::<H, I>::extract(Some(salt), secret);
    let mut key: GenericArray<u8, <<A as Aead>::AeadImpl as KeySizeUser>::KeySize> =
        Default::default();
    hk.expand(LABEL_AEAD_KEY.as_bytes(), &mut key)
        .map_err(|_| Error::InvalidInput)?;
    let mut nonce: GenericArray<u8, <<A as Aead>::AeadImpl as AeadCore>::NonceSize> =
        Default::default();
    hk.expand(LABEL_AEAD_NONCE.as_bytes(), &mut nonce)
        .map_err(|_| Error::InvalidInput)?;

    Ok((prk, key, nonce))
}
