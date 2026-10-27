use crate::{Error, MAX_PACKET_BYTES, Result};
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
        if self.0.len().saturating_add(v.len()).saturating_add(4) > MAX_PACKET_BYTES {
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
        if bytes.len() > MAX_PACKET_BYTES {
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
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
    pub fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_fields_round_trip() {
        let mut e = Encoder::new();
        e.byte(7);
        e.u32(0x0102_0304);
        e.u64(0x0102_0304_0506_0708);
        e.fixed(&[9, 9, 9]);
        let mut d = Decoder::new(&e.0).unwrap();
        assert_eq!(d.byte().unwrap(), 7);
        assert_eq!(d.u32().unwrap(), 0x0102_0304);
        assert_eq!(d.u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(d.array::<3>().unwrap(), [9, 9, 9]);
        d.finish().unwrap();
    }

    #[test]
    fn bytes_and_text_round_trip() {
        let mut e = Encoder::new();
        e.bytes(b"payload").unwrap();
        e.text("hello").unwrap();
        let mut d = Decoder::new(&e.0).unwrap();
        assert_eq!(d.bytes(64).unwrap(), b"payload");
        assert_eq!(d.text(64).unwrap(), "hello");
        d.finish().unwrap();
    }

    #[test]
    fn decoder_bytes_rejects_length_over_max() {
        let mut e = Encoder::new();
        e.bytes(b"0123456789").unwrap();
        let mut d = Decoder::new(&e.0).unwrap();
        assert_eq!(d.bytes(4), Err(Error::Limit));
    }

    #[test]
    fn decoder_bytes_declaring_more_than_present_is_corrupt() {
        // A hand-built frame that declares a 100-byte payload but supplies none.
        let mut e = Encoder::new();
        e.u32(100);
        let mut d = Decoder::new(&e.0).unwrap();
        assert_eq!(d.bytes(1000), Err(Error::Corrupt));
    }

    #[test]
    fn take_past_the_end_is_corrupt_not_a_panic() {
        let bytes = [1u8, 2, 3];
        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.take(2).unwrap(), &[1, 2]);
        assert_eq!(d.take(2), Err(Error::Corrupt));
    }

    #[test]
    fn array_on_a_truncated_tail_is_corrupt() {
        let bytes = [1u8, 2];
        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.array::<4>(), Err(Error::Corrupt));
    }

    #[test]
    fn text_rejects_invalid_utf8() {
        let mut e = Encoder::new();
        e.bytes(&[0xff, 0xfe]).unwrap();
        let mut d = Decoder::new(&e.0).unwrap();
        assert_eq!(d.text(64), Err(Error::Corrupt));
    }

    #[test]
    fn finish_rejects_unconsumed_trailing_bytes() {
        let bytes = [1u8, 2, 3];
        let mut d = Decoder::new(&bytes).unwrap();
        d.byte().unwrap();
        assert_eq!(d.finish(), Err(Error::Corrupt));
    }

    #[test]
    fn remaining_tracks_position() {
        let bytes = [1u8, 2, 3, 4];
        let mut d = Decoder::new(&bytes).unwrap();
        assert_eq!(d.remaining(), 4);
        d.take(1).unwrap();
        assert_eq!(d.remaining(), 3);
        d.take(3).unwrap();
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn decoder_new_rejects_a_buffer_over_the_packet_limit() {
        let bytes = vec![0u8; MAX_PACKET_BYTES + 1];
        assert_eq!(Decoder::new(&bytes).err(), Some(Error::Limit));
    }

    #[test]
    fn encoder_bytes_rejects_growing_past_the_packet_limit() {
        let mut e = Encoder::new();
        let v = vec![0u8; MAX_PACKET_BYTES - 3];
        assert_eq!(e.bytes(&v), Err(Error::Limit));
    }
}
