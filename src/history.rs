use crate::{
    CipherStore, Error, HISTORY_PAGE_SIZE, Result, Revision, VaultId, crypto::Packet,
    custody::load_packet,
};

pub(crate) fn at<S: CipherStore + ?Sized>(
    store: &S,
    vault: VaultId,
    index: u64,
) -> Result<Option<Revision>> {
    let rows = store.history_page(vault, index.checked_sub(1), 1)?;
    if rows.len() > 1 || rows.first().is_some_and(|r| r.index != index) {
        return Err(Error::Corrupt);
    }
    Ok(rows.first().copied())
}

/// Streams authenticated packet linkage with O(page size + one packet) working
/// memory. The caller additionally authenticates plaintext when keys are held.
pub(crate) fn walk<S: CipherStore + ?Sized>(
    store: &S,
    vault: VaultId,
    anchor: Revision,
    mut visit: impl FnMut(Revision, Packet) -> Result<()>,
) -> Result<()> {
    if store.head(vault)? != Some(anchor) {
        return Err(Error::StaleAnchor);
    }
    let mut previous: Option<Revision> = None;
    let mut header = None;
    loop {
        let page = store.history_page(vault, previous.map(|r| r.index), HISTORY_PAGE_SIZE)?;
        if page.is_empty() {
            if previous != Some(anchor) {
                return Err(Error::Corrupt);
            }
            break;
        }
        if page.len() > HISTORY_PAGE_SIZE {
            return Err(Error::Corrupt);
        }
        for r in page {
            let expected = match previous {
                None => 0,
                Some(p) => p.index.checked_add(1).ok_or(Error::Corrupt)?,
            };
            if r.index != expected || r.index > anchor.index {
                return Err(Error::Corrupt);
            }
            let packet = load_packet(store, r)?;
            if packet.header.vault != vault
                || packet.previous != previous
                || header.as_ref().is_some_and(|h| *h != packet.header)
                || store.resolve(vault, packet.request)? != Some(r)
            {
                return Err(Error::Corrupt);
            }
            if header.is_none() {
                header = Some(packet.header.clone());
            }
            visit(r, packet)?;
            previous = Some(r);
        }
        // Even at the selected head, request the next page to reject extra rows.
    }
    if store.head(vault)? != Some(anchor) {
        return Err(Error::StaleAnchor);
    }
    Ok(())
}
