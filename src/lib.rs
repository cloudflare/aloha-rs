#![deny(missing_docs)]
//! Implements draft-ietf-ohai-ohttp-06.

// TODO:
//   check all the return error
//   unify function names

use aead::{AeadCore, KeySizeUser};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use generic_array::typenum::Unsigned;
use hpke::aead::Aead;
use hpke::kdf::Kdf;
use hpke::kem::{DhP256HkdfSha256, Kem, X25519HkdfSha256};
use hpke::{Deserializable, HpkeError, Serializable};
use rand::Rng;
use rand::{CryptoRng, RngCore};
use thiserror::Error as ThisError;

//mod iface;
pub mod bhttp;
mod crypt;

use crypt::{decrypt_req, decrypt_res, encrypt_req, encrypt_res};

/// HTTP media type for key config.
pub const MT_KEY_CONFIG: &str = "application/ohttp-keys";
/// HTTP media type for oHTTP request.
pub const MT_OHTTP_REQ: &str = "message/ohttp-req";
/// HTTP media type for oHTTP response.
pub const MT_OHTTP_RES: &str = "message/ohttp-res";

/// Reexport of several HPKE algorithm IDs.
pub mod id {
    use hpke::aead::{Aead, AesGcm128, AesGcm256, ChaCha20Poly1305};
    use hpke::kdf::{self, Kdf};
    use hpke::kem::{self, Kem};

    /// Supported KEM IDs
    #[repr(u16)]
    pub enum KemId {
        /// DhP256HkdfSha256
        DHP256HKDFSHA256 = kem::DhP256HkdfSha256::KEM_ID,
        /// X25519HkdfSha256
        X25519HKDFSHA256 = kem::X25519HkdfSha256::KEM_ID,
    }

    /// Supported KDF IDs
    #[repr(u16)]
    pub enum KdfId {
        /// HkdfSha256
        HKDFSHA256 = kdf::HkdfSha256::KDF_ID,
        /// HkdfSha384
        HKDFSHA384 = kdf::HkdfSha384::KDF_ID,
        /// HkdfSha512
        HKDFSHA512 = kdf::HkdfSha512::KDF_ID,
    }

    /// Supported AEAD IDs
    #[repr(u16)]
    pub enum AeadId {
        /// AesGcm128
        AESGCM128 = AesGcm128::AEAD_ID,
        /// AesGcm256
        AESGCM256 = AesGcm256::AEAD_ID,
        /// ChaCha20Poly1305
        CHACHA20POLY1305 = ChaCha20Poly1305::AEAD_ID,
    }
}

const LABEL_REQ: &str = "message/bhttp request";
const LABEL_RES: &str = "message/bhttp response";

const LABEL_AEAD_KEY: &str = "key";
const LABEL_AEAD_NONCE: &str = "nonce";

const fn aead_key_size<A: Aead>() -> usize {
    <<A as Aead>::AeadImpl as KeySizeUser>::KeySize::USIZE
}

const fn aead_nonce_size<A: Aead>() -> usize {
    <<A as Aead>::AeadImpl as AeadCore>::NonceSize::USIZE
}

const fn res_nonce_size<A: Aead>() -> usize {
    let a = aead_key_size::<A>();
    let b = aead_nonce_size::<A>();

    // get the max from the two in compile time
    [a, b][(a < b) as usize]
}

/// Errors used in oHTTP.
#[derive(ThisError, Debug, Clone)]
pub enum Error {
    /// Input data is too short.
    #[error("Input data is too short")]
    ShortBuf,
    /// Input data is invalid.
    #[error("Input data is invalid")]
    InvalidInput,
    /// Kem is not supported.
    #[error("Kem is not supported")]
    UnsupportedKem,
    /// Kdf is not supported.
    #[error("kdf is not supported")]
    UnsupportedKdf,
    /// Aead is not supported.
    #[error("Aead is not supported")]
    UnsupportedAead,

    /// No private key in config. Happens when calling server side
    /// functions on client config.
    #[error("No private key in config")]
    NoPrivateKey,

    /// No ID provided in config.
    #[error("No ID provided in config")]
    MissingId,

    /// No public key provided in config.
    #[error("No public key provided in config")]
    MissingPublicKey,

    /// No symmetric algorithm set provided in config.
    #[error("No symmetric algorithm set provided in config")]
    MissingSymAlg,

    /// Aead is not supported.
    #[error("Aead error")]
    AeadError,

    /// Errors from hpke crate.
    #[error(transparent)]
    Hpke(#[from] HpkeError),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
enum PubKey {
    X25519HkdfSha256(<X25519HkdfSha256 as Kem>::PublicKey),
    DhP256HkdfSha256(<DhP256HkdfSha256 as Kem>::PublicKey),
}

#[derive(Clone)]
enum PrivKey {
    X25519HkdfSha256(<X25519HkdfSha256 as Kem>::PrivateKey),
    DhP256HkdfSha256(<DhP256HkdfSha256 as Kem>::PrivateKey),
}

fn compose_to<BM: BufMut, B: Buf>(buf: &mut BM, data: B) -> Result<()> {
    if buf.remaining_mut() < data.remaining() {
        return Err(Error::ShortBuf);
    }

    buf.put(data);
    Ok(())
}

/// Unified Config for both client and server.
#[derive(Clone)]
pub struct Config {
    id: u8,
    pub_key: PubKey,
    priv_key: Option<PrivKey>,
    algs: SymAlgs,
}

impl Config {
    /// Create a builder for building a server side config.
    pub fn builder() -> ConfigBuilder {
        Default::default()
    }

    /// Return the KEM ID supported by the config.
    pub fn kem_id(&self) -> u16 {
        match &self.pub_key {
            PubKey::X25519HkdfSha256(_) => <X25519HkdfSha256 as Kem>::KEM_ID,
            PubKey::DhP256HkdfSha256(_) => <DhP256HkdfSha256 as Kem>::KEM_ID,
        }
    }

    fn try_as_header(&self, i: usize) -> Result<Header> {
        let alg = self.algs.try_get(i)?;

        Ok(Header {
            cid: self.id,
            kem_id: self.kem_id(),
            kdf_id: alg.kdf_id,
            aead_id: alg.aead_id,
        })
    }

    /// Encrypt a request, return the encrypted data and a context,
    /// which can be used to decrypt the response later.
    pub fn encrypt_req<R: RngCore + CryptoRng>(
        &self,
        alg_idx: usize,
        req: &[u8],
        rng: &mut R,
    ) -> Result<(BytesMut, Ctx)> {
        let hdr = self.try_as_header(alg_idx)?;
        match &self.pub_key {
            PubKey::X25519HkdfSha256(k) => encrypt_req::<X25519HkdfSha256, _>(hdr, k, req, rng),
            PubKey::DhP256HkdfSha256(k) => encrypt_req::<DhP256HkdfSha256, _>(hdr, k, req, rng),
        }
    }

    /// Parse a client side config from a given buffer.
    pub fn parse<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 1 + 2 {
            return Err(Error::InvalidInput);
        }

        let id = buf.get_u8();
        let kem_id = buf.get_u16();
        let public_key = match kem_id {
            X25519HkdfSha256::KEM_ID => {
                let key_len = <X25519HkdfSha256 as Kem>::PublicKey::size();
                if buf.remaining() < key_len {
                    return Err(Error::InvalidInput);
                }
                PubKey::X25519HkdfSha256(<X25519HkdfSha256 as Kem>::PublicKey::from_bytes(
                    &buf.copy_to_bytes(key_len),
                )?)
            }
            DhP256HkdfSha256::KEM_ID => {
                let key_len = <DhP256HkdfSha256 as Kem>::PublicKey::size();
                if buf.remaining() < key_len {
                    return Err(Error::InvalidInput);
                }
                PubKey::DhP256HkdfSha256(<DhP256HkdfSha256 as Kem>::PublicKey::from_bytes(
                    &buf.copy_to_bytes(key_len),
                )?)
            }
            _ => return Err(Error::UnsupportedKem),
        };
        if buf.remaining() < 2 {
            return Err(Error::InvalidInput);
        }
        let algs_len = buf.get_u16();
        let (_, rem) = (
            algs_len as usize / SymAlgs::ITEM_SIZE,
            algs_len as usize % SymAlgs::ITEM_SIZE,
        );
        if rem != 0 {
            return Err(Error::InvalidInput);
        }
        let algs = SymAlgs(buf.copy_to_bytes(algs_len as usize));
        Ok(Self {
            id,
            pub_key: public_key,
            priv_key: None,
            algs,
        })
    }

    /// Compose a client side config into given buffer.
    pub fn compose<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        if buf.remaining_mut() < 1 + 2 {
            return Err(Error::InvalidInput);
        }

        buf.put_u8(self.id);
        buf.put_u16(self.kem_id());
        match &self.pub_key {
            PubKey::X25519HkdfSha256(k) => compose_to(buf, k.to_bytes().as_slice())?,
            PubKey::DhP256HkdfSha256(k) => compose_to(buf, k.to_bytes().as_slice())?,
        };
        if buf.remaining_mut() < 2 {
            return Err(Error::ShortBuf);
        }
        buf.put_u16((self.algs.len() * SymAlgs::ITEM_SIZE) as u16);
        compose_to(buf, self.algs.0.as_ref())?;
        Ok(())
    }

    /// Get a client side config.
    pub fn get_client(&self) -> Self {
        Self {
            id: self.id,
            pub_key: self.pub_key.clone(),
            priv_key: None,
            algs: self.algs.clone(),
        }
    }

    fn validate_header(&self, buf: &[u8]) -> Result<Header> {
        let hdr = Header::from_slice(buf)?;
        if hdr.cid != self.id {
            return Err(Error::InvalidInput);
        }

        let mut found = false;
        for i in 0..self.algs.len() {
            let alg = self.algs.get(i);
            if alg.kdf_id == hdr.kdf_id && alg.aead_id == hdr.aead_id {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::InvalidInput);
        }
        match &self.pub_key {
            PubKey::X25519HkdfSha256(_) if hdr.kem_id == X25519HkdfSha256::KEM_ID => (),
            PubKey::DhP256HkdfSha256(_) if hdr.kem_id == DhP256HkdfSha256::KEM_ID => (),
            _ => return Err(Error::InvalidInput),
        }
        Ok(hdr)
    }

    /// Decrypt a request.
    pub fn decrypt_req(&self, enc_req: &[u8]) -> Result<(BytesMut, Ctx)> {
        let buf = BytesMut::from(enc_req);
        self.decrypt_req_in_place(buf)
    }

    /// Decrypt the requet in place using the provided BytesMut.
    pub fn decrypt_req_in_place(&self, enc_req: BytesMut) -> Result<(BytesMut, Ctx)> {
        let hdr = self.validate_header(&enc_req)?;

        match self.priv_key.as_ref() {
            Some(PrivKey::X25519HkdfSha256(key)) => {
                decrypt_req::<X25519HkdfSha256>(hdr, enc_req, key)
            }
            Some(PrivKey::DhP256HkdfSha256(key)) => {
                decrypt_req::<DhP256HkdfSha256>(hdr, enc_req, key)
            }
            None => Err(Error::NoPrivateKey),
        }
    }
}

/// A builder to build config.
#[derive(Default, Clone)]
pub struct ConfigBuilder {
    id: Option<u8>,
    pub_key: Option<PubKey>,
    priv_key: Option<PrivKey>,
    algs: BytesMut,
}

impl ConfigBuilder {
    /// Provide the config id.
    pub fn with_id(mut self, id: u8) -> Self {
        self.id = Some(id);
        self
    }

    /// Generate keypair from a given ikm.
    pub fn gen_keypair_with(mut self, kem: id::KemId, ikm: &[u8]) -> Self {
        match kem {
            id::KemId::X25519HKDFSHA256 => {
                let (sk, pk) = X25519HkdfSha256::derive_keypair(ikm);
                self.priv_key = Some(PrivKey::X25519HkdfSha256(sk));
                self.pub_key = Some(PubKey::X25519HkdfSha256(pk));
            }
            id::KemId::DHP256HKDFSHA256 => {
                let (sk, pk) = DhP256HkdfSha256::derive_keypair(ikm);
                self.priv_key = Some(PrivKey::DhP256HkdfSha256(sk));
                self.pub_key = Some(PubKey::DhP256HkdfSha256(pk));
            }
        }
        self
    }

    /// Generate keypair using passed rng.
    pub fn gen_keypair<R: RngCore + CryptoRng>(self, kem: id::KemId, rng: &mut R) -> Self {
        // TODO: make ikm size configurable
        let mut ikm = [0u8; 32];
        rng.fill(&mut ikm);
        self.gen_keypair_with(kem, &ikm)
    }

    /// Push a symmetric algorithm pair into the support list.
    pub fn push_alg(mut self, kdf: id::KdfId, aead: id::AeadId) -> Self {
        self.algs.put_u16(kdf as u16);
        self.algs.put_u16(aead as u16);
        self
    }

    /// Consume the builder, and generate a config if all the
    /// information have been provided.
    pub fn build(self) -> Result<Config> {
        let id = self.id.ok_or(Error::MissingId)?;
        let pub_key = self.pub_key.ok_or(Error::MissingPublicKey)?;
        let priv_key = self.priv_key;
        let algs = if self.algs.is_empty() {
            Err(Error::MissingSymAlg)
        } else {
            Ok(SymAlgs(self.algs.freeze()))
        }?;

        Ok(Config {
            id,
            pub_key,
            priv_key,
            algs,
        })
    }
}

/// A context used in either client side or server side to carry
/// necessary information for handling response later.
#[derive(Default)]
pub struct Ctx {
    hdr: Header,
    encapped_key: Bytes,
    secret: Bytes,
}

impl Ctx {
    /// Used by the server side, encrypt a response.
    pub fn encrypt_res<R: RngCore + CryptoRng>(&self, res: &[u8], rng: &mut R) -> Result<BytesMut> {
        encrypt_res(self.hdr, res, &self.encapped_key, &self.secret, rng)
    }

    /// Used by the client side, decrypt a response.
    pub fn decrypt_res(&self, enc_res: &[u8]) -> Result<BytesMut> {
        let buf = BytesMut::from(enc_res);
        self.decrypt_res_in_place(buf)
    }

    /// Used by the client side, decrypt a response in place.
    pub fn decrypt_res_in_place(&self, enc_res: BytesMut) -> Result<BytesMut> {
        decrypt_res(self.hdr, enc_res, &self.encapped_key, &self.secret)
    }

    /// Serialize the context into a given buffer.
    pub fn compose<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        self.hdr.compose(buf)?;
        compose_to(buf, &mut self.encapped_key.as_ref())?;
        compose_to(buf, &mut self.secret.as_ref())?;
        Ok(())
    }

    /// Deserialize the context from a given buffer.
    pub fn parse<B: Buf>(buf: &mut B) -> Result<Self> {
        let hdr = Header::parse(buf)?;
        let size = match hdr.kem_id {
            <DhP256HkdfSha256 as Kem>::KEM_ID => <DhP256HkdfSha256 as Kem>::EncappedKey::size(),
            <X25519HkdfSha256 as Kem>::KEM_ID => <X25519HkdfSha256 as Kem>::EncappedKey::size(),
            _ => return Err(Error::UnsupportedKem),
        };

        if buf.remaining() < size {
            return Err(Error::InvalidInput);
        }
        let encapped_key = buf.copy_to_bytes(size);
        let secret = buf.copy_to_bytes(buf.remaining());
        Ok(Self {
            hdr,
            encapped_key,
            secret,
        })
    }
}

#[derive(Debug, Clone)]
struct SymAlgs(Bytes);

impl SymAlgs {
    const ITEM_SIZE: usize = 4;

    fn len(&self) -> usize {
        self.0.len() / Self::ITEM_SIZE
    }

    // panic when n > self.len()
    fn get(&self, n: usize) -> SymAlg {
        let mut buf = &self.0[n * Self::ITEM_SIZE..(n + 1) * Self::ITEM_SIZE];
        SymAlg {
            kdf_id: buf.get_u16(),
            aead_id: buf.get_u16(),
        }
    }

    fn try_get(&self, n: usize) -> Result<SymAlg> {
        let end = (n + 1) * Self::ITEM_SIZE;
        if end > self.0.len() {
            return Err(Error::InvalidInput);
        }
        let mut buf = &self.0[n * Self::ITEM_SIZE..end];
        Ok(SymAlg {
            kdf_id: buf.get_u16(),
            aead_id: buf.get_u16(),
        })
    }
}

#[derive(Debug)]
struct SymAlg {
    kdf_id: u16,
    aead_id: u16,
}

#[derive(Debug, Clone, Copy, Default)]
struct Header {
    cid: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
}

impl Header {
    // config id + kem id + kdf id + aead id
    const SIZE: usize = 1 + 2 + 2 + 2;

    fn from_slice(mut buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::InvalidInput);
        }

        Ok(Self {
            cid: buf.get_u8(),
            kem_id: buf.get_u16(),
            kdf_id: buf.get_u16(),
            aead_id: buf.get_u16(),
        })
    }

    fn parse<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < Self::SIZE {
            return Err(Error::InvalidInput);
        }

        Ok(Self {
            cid: buf.get_u8(),
            kem_id: buf.get_u16(),
            kdf_id: buf.get_u16(),
            aead_id: buf.get_u16(),
        })
    }

    fn compose<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        if buf.remaining_mut() < Self::SIZE {
            return Err(Error::InvalidInput);
        }

        buf.put_u8(self.cid);
        buf.put_u16(self.kem_id);
        buf.put_u16(self.kdf_id);
        buf.put_u16(self.aead_id);

        Ok(())
    }
}

fn compose_header<KEM, KDF, AEAD, B>(cid: u8, buf: &mut B) -> Result<()>
where
    KEM: Kem,
    KDF: Kdf,
    AEAD: Aead,
    B: BufMut,
{
    if buf.remaining_mut() < Header::SIZE {
        return Err(Error::InvalidInput);
    }

    buf.put_u8(cid);
    buf.put_u16(<KEM as Kem>::KEM_ID);
    buf.put_u16(<KDF as Kdf>::KDF_ID);
    buf.put_u16(<AEAD as Aead>::AEAD_ID);

    Ok(())
}

fn compose_info<KEM, KDF, AEAD, B>(cid: u8, label: &[u8], buf: &mut B) -> Result<()>
where
    KEM: Kem,
    KDF: Kdf,
    AEAD: Aead,
    B: BufMut,
{
    if buf.remaining_mut() < label.len() + 1 + Header::SIZE {
        return Err(Error::InvalidInput);
    }

    buf.put(label);
    buf.put_u8(0);
    compose_header::<KEM, KDF, AEAD, _>(cid, buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use hpke::aead::{Aead, AesGcm128, AesGcm256, ChaCha20Poly1305};
    use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rstest::*;

    #[test]
    fn config() {
        let example_config = hex!(
            "
            01002031 e1f05a74 01021152 20e9af91
            8f738674 aec95f54 db6e04eb 705aae8e
            79815500 08000100 01000100 03
            "
        );

        let conf = Config::parse(&mut example_config.as_slice()).unwrap();

        assert_eq!(1, conf.id);
        assert_eq!(X25519HkdfSha256::KEM_ID, conf.kem_id());
        assert_eq!(2, conf.algs.len());
        let alg = conf.algs.get(0);
        assert_eq!(HkdfSha256::KDF_ID, alg.kdf_id);
        assert_eq!(AesGcm128::AEAD_ID, alg.aead_id);
        let alg = conf.algs.get(1);
        assert_eq!(HkdfSha256::KDF_ID, alg.kdf_id);
        assert_eq!(ChaCha20Poly1305::AEAD_ID, alg.aead_id);
        assert!(conf.algs.try_get(2).is_err());

        let mut buf = BytesMut::new();
        conf.compose(&mut buf).unwrap();
        assert_eq!(example_config.as_slice(), buf.freeze());
    }

    fn enc_dec_with_config(conf: &Config) {
        // create RNG with deterministic seed
        let mut rng = StdRng::from_seed([0; 32]);
        let srv_conf = conf;
        let cli_conf = conf.get_client();

        let req = b"";
        let (enc_req, _) = cli_conf.encrypt_req(0, req, &mut rng).unwrap();
        let (dec_req, _) = srv_conf.decrypt_req(&enc_req).unwrap();
        assert_eq!(req, dec_req.as_ref());

        let req = b"hello";
        let (enc_req, cli_ctx) = cli_conf.encrypt_req(0, req, &mut rng).unwrap();
        let (dec_req, srv_ctx) = srv_conf.decrypt_req(&enc_req).unwrap();
        assert_eq!(req, dec_req.as_ref());

        let res = b"world";
        let enc_res = srv_ctx.encrypt_res(&res[..], &mut rng).unwrap();
        let dec_res = cli_ctx.decrypt_res(&enc_res).unwrap();
        assert_eq!(&res[..], &dec_res);
    }

    #[rstest]
    fn crypto_algs(
        #[values(X25519HkdfSha256::KEM_ID, DhP256HkdfSha256::KEM_ID)] kem_id: u16,
        #[values(HkdfSha256::KDF_ID, HkdfSha384::KDF_ID, HkdfSha512::KDF_ID)] kdf_id: u16,
        #[values(AesGcm128::AEAD_ID, AesGcm256::AEAD_ID, ChaCha20Poly1305::AEAD_ID)] aead_id: u16,
    ) {
        // use static ikm to generate key pair
        let ikm = [0u8; 32];

        let mut algs = BytesMut::new();
        algs.put_u16(kdf_id);
        algs.put_u16(aead_id);
        let algs = algs.freeze();
        let key_pair = match kem_id {
            X25519HkdfSha256::KEM_ID => {
                let pair = <X25519HkdfSha256 as Kem>::derive_keypair(&ikm);
                (
                    PrivKey::X25519HkdfSha256(pair.0),
                    PubKey::X25519HkdfSha256(pair.1),
                )
            }
            DhP256HkdfSha256::KEM_ID => {
                let pair = <DhP256HkdfSha256 as Kem>::derive_keypair(&ikm);
                (
                    PrivKey::DhP256HkdfSha256(pair.0),
                    PubKey::DhP256HkdfSha256(pair.1),
                )
            }
            _ => unimplemented!(),
        };
        let conf = Config {
            id: 1,
            priv_key: Some(key_pair.0),
            pub_key: key_pair.1,
            algs: SymAlgs(algs),
        };
        enc_dec_with_config(&conf);
    }
}
