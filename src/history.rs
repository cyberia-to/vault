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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Header, Keys};
    use crate::store::identity;
    use crate::{RequestId, StoredRevision};
    use std::cell::RefCell;
    use zeroize::Zeroizing;

    const PASSWORD: &[u8] = b"synthetic-unlock-passphrase";
    const RECOVERY: [u8; 32] = [9; 32];

    #[derive(Default)]
    struct MockStore {
        rows: RefCell<Vec<(Revision, Vec<u8>)>>,
        requests: RefCell<Vec<(RequestId, Revision)>>,
        oversized_page: bool,
        ignore_limit: bool,
    }

    impl MockStore {
        fn push(&self, revision: Revision, bytes: Vec<u8>, request: RequestId) {
            self.rows.borrow_mut().push((revision, bytes));
            self.requests.borrow_mut().push((request, revision));
        }
    }

    impl CipherStore for MockStore {
        fn head(&self, _vault: VaultId) -> Result<Option<Revision>> {
            Ok(self.rows.borrow().last().map(|(r, _)| *r))
        }
        fn read(&self, revision: Revision) -> Result<StoredRevision> {
            self.rows
                .borrow()
                .iter()
                .find(|(r, _)| r.index == revision.index)
                .map(|(r, b)| StoredRevision { revision: *r, bytes: b.clone() })
                .ok_or(Error::NotFound)
        }
        fn history_page(
            &self,
            _vault: VaultId,
            after: Option<u64>,
            limit: usize,
        ) -> Result<Vec<Revision>> {
            if self.oversized_page {
                let filler = self.rows.borrow()[0].0;
                return Ok(vec![filler; HISTORY_PAGE_SIZE + 1]);
            }
            let take = if self.ignore_limit { usize::MAX } else { limit };
            Ok(self
                .rows
                .borrow()
                .iter()
                .filter(|(r, _)| match after {
                    None => true,
                    Some(a) => r.index > a,
                })
                .take(take)
                .map(|(r, _)| *r)
                .collect())
        }
        fn resolve(&self, _vault: VaultId, request: RequestId) -> Result<Option<Revision>> {
            Ok(self
                .requests
                .borrow()
                .iter()
                .find(|(req, _)| *req == request)
                .map(|(_, r)| *r))
        }
        fn append(
            &self,
            _vault: VaultId,
            _request: RequestId,
            _expected: Option<Revision>,
            _bytes: Vec<u8>,
        ) -> Result<Revision> {
            unimplemented!("history::walk/at never append")
        }
    }

    /// Seals one real, decodable packet — encryption included — and returns
    /// its revision, wire bytes and request id, ready to push into a store.
    fn seal(header: &Header, keys: &Keys, previous: Option<Revision>) -> (Revision, Vec<u8>, RequestId) {
        let request = RequestId::random().unwrap();
        let packet = Packet::seal(
            header.clone(),
            keys,
            request,
            previous,
            Zeroizing::new(b"secret".to_vec()),
        )
        .unwrap();
        let bytes = packet.encode().unwrap();
        let revision = Revision { index: packet.index, commit: identity(&bytes) };
        (revision, bytes, request)
    }

    fn chain(store: &MockStore, header: &Header, keys: &Keys, n: usize) -> Vec<Revision> {
        let mut previous = None;
        let mut revisions = Vec::new();
        for _ in 0..n {
            let (revision, bytes, request) = seal(header, keys, previous);
            store.push(revision, bytes, request);
            previous = Some(revision);
            revisions.push(revision);
        }
        revisions
    }

    #[test]
    fn walk_visits_every_revision_in_order() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        let revisions = chain(&store, &header, &keys, 3);

        let mut seen = Vec::new();
        walk(&store, vault, *revisions.last().unwrap(), |r, packet| {
            seen.push((r, packet.index));
            Ok(())
        })
        .unwrap();

        assert_eq!(seen, vec![(revisions[0], 0), (revisions[1], 1), (revisions[2], 2)]);
    }

    #[test]
    fn walk_rejects_stale_anchor() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        let revisions = chain(&store, &header, &keys, 2);

        let err = walk(&store, vault, revisions[0], |_, _| Ok(())).unwrap_err();
        assert_eq!(err, Error::StaleAnchor);
    }

    #[test]
    fn walk_rejects_non_contiguous_index() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        // Seal a real chain of three so the second packet's own linkage stays
        // internally consistent, but never store the middle row — the store
        // itself now has a gap at index 1.
        let (rev0, bytes0, req0) = seal(&header, &keys, None);
        let (rev1, _bytes1, _req1) = seal(&header, &keys, Some(rev0));
        let (rev2, bytes2, req2) = seal(&header, &keys, Some(rev1));
        store.push(rev0, bytes0, req0);
        store.push(rev2, bytes2, req2);

        let err = walk(&store, vault, rev2, |_, _| Ok(())).unwrap_err();
        assert_eq!(err, Error::Corrupt);
    }

    #[test]
    fn walk_rejects_page_larger_than_the_requested_limit() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let mut store = MockStore::default();
        let revisions = chain(&store, &header, &keys, 1);
        store.oversized_page = true;

        let err = walk(&store, vault, revisions[0], |_, _| Ok(())).unwrap_err();
        assert_eq!(err, Error::Corrupt);
    }

    #[test]
    fn walk_rejects_a_previous_link_that_does_not_match_what_was_stored() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        // The packet actually stored at index 0 (rev0b) is a different seal
        // than the one (rev0) the index-1 packet's own AAD commits to as its
        // `previous` — same index, different commit.
        let (rev0, _bytes0, _req0) = seal(&header, &keys, None);
        let (rev0b, bytes0b, req0b) = seal(&header, &keys, None);
        let (rev1, bytes1, req1) = seal(&header, &keys, Some(rev0));
        store.push(rev0b, bytes0b, req0b);
        store.push(rev1, bytes1, req1);
        assert_eq!(rev0.index, rev0b.index);
        assert_ne!(rev0.commit, rev0b.commit);

        let err = walk(&store, vault, rev1, |_, _| Ok(())).unwrap_err();
        assert_eq!(err, Error::Corrupt);
    }

    #[test]
    fn walk_rejects_a_header_bound_to_a_different_vault() {
        let signing_vault = VaultId::random().unwrap();
        let other_vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(signing_vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        let revisions = chain(&store, &header, &keys, 1);

        let err = walk(&store, other_vault, revisions[0], |_, _| Ok(())).unwrap_err();
        assert_eq!(err, Error::Corrupt);
    }

    #[test]
    fn walk_rejects_a_request_the_store_cannot_resolve_back_to_its_revision() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        let (revision, bytes, _request) = seal(&header, &keys, None);
        // Push the row directly, skipping request-index registration.
        store.rows.borrow_mut().push((revision, bytes));

        let err = walk(&store, vault, revision, |_, _| Ok(())).unwrap_err();
        assert_eq!(err, Error::Corrupt);
    }

    #[test]
    fn at_finds_the_revision_at_the_requested_index() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        let revisions = chain(&store, &header, &keys, 3);

        assert_eq!(at(&store, vault, 1).unwrap(), Some(revisions[1]));
    }

    #[test]
    fn at_returns_none_past_the_end_of_history() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        chain(&store, &header, &keys, 1);

        assert_eq!(at(&store, vault, 5).unwrap(), None);
    }

    #[test]
    fn at_rejects_a_store_that_returns_more_than_one_row() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let mut store = MockStore::default();
        chain(&store, &header, &keys, 3);
        store.ignore_limit = true;

        let err = at(&store, vault, 1).unwrap_err();
        assert_eq!(err, Error::Corrupt);
    }

    #[test]
    fn at_rejects_a_row_whose_index_does_not_match_the_request() {
        let vault = VaultId::random().unwrap();
        let (header, keys) = Header::create(vault, PASSWORD, &RECOVERY).unwrap();
        let store = MockStore::default();
        // Seal a two-link chain but only store the second row — asking for
        // index 0 finds a real row (index 1) that does not match.
        let (rev0, _bytes0, _req0) = seal(&header, &keys, None);
        let (rev1, bytes1, req1) = seal(&header, &keys, Some(rev0));
        store.push(rev1, bytes1, req1);

        let err = at(&store, vault, 0).unwrap_err();
        assert_eq!(err, Error::Corrupt);
    }
}
