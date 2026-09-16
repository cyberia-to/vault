use crate::{Error, MAX_SNAPSHOT_BYTES, Result};
use zeroize::Zeroizing;

pub(crate) struct Encoder(pub Zeroizing<Vec<u8>>);
impl Encoder {
    pub fn new() -> Self {
        Self(Zeroizing::new(Vec::new()))
    }
    pub fn byte(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend(v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend(v.to_le_bytes());
    }
    pub fn fixed(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
    pub fn bytes(&mut self, v: &[u8]) -> Result<()> {
        let len = u32::try_from(v.len()).map_err(|_| Error::Limit)?;
        if self.0.len().saturating_add(v.len()).saturating_add(4) > MAX_SNAPSHOT_BYTES {
            return Err(Error::Limit);
        }
        self.u32(len);
        self.fixed(v);
        Ok(())
    }
    pub fn text(&mut self, v: &str) -> Result<()> {
        self.bytes(v.as_bytes())
    }
}
pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Limit);
        }
        Ok(Self { bytes, pos: 0 })
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Limit)?;
        let bytes = self.bytes.get(self.pos..end).ok_or(Error::Corrupt)?;
        self.pos = end;
        Ok(bytes)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(Error::Limit);
        }
        self.take(n)
    }
    pub fn text(&mut self, max: usize) -> Result<String> {
        String::from_utf8(self.bytes(max)?.to_vec()).map_err(|_| Error::Corrupt)
    }
    pub fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
}
