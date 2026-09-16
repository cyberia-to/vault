use crate::{
    Context, EntryInfo, Error, Intent, IntentKind, Operation, RequestId, Result, SecretRef,
    VaultId, Ward,
};

pub enum Grant {
    Create,
    Inspect,
    Put(EntryInfo),
    Delete(SecretRef, u64),
    Use(Operation),
}

/// Constructed only by this local operator process while it holds the host lock.
/// OS ownership plus a successful unlock authenticates the process's Context.
pub struct Owner {
    pub vault: VaultId,
    pub context: Context,
    pub request: RequestId,
    pub grant: Grant,
}
impl Ward for Owner {
    fn with_authorization<T>(
        &self,
        intent: &Intent,
        action: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T> {
        if intent.vault != self.vault || intent.context != self.context {
            return Err(Error::Denied);
        }
        let allowed = match (&self.grant, &intent.kind) {
            (Grant::Inspect, IntentKind::Inspect) => true,
            (Grant::Create, IntentKind::Create) => true,
            (
                Grant::Put(expected),
                IntentKind::Put {
                    entry,
                    expected_version: None,
                },
            ) => {
                expected.id == entry.id
                    && expected.kind == entry.kind
                    && expected.policy == entry.policy
                    && expected.label == entry.label
                    && expected.scope == entry.scope
                    && expected.revealable == entry.revealable
            }
            (
                Grant::Delete(id, version),
                IntentKind::Delete {
                    secret,
                    expected_version,
                },
            ) => id == secret && version == expected_version,
            (
                Grant::Use(expected),
                IntentKind::Prepare { operation, .. } | IntentKind::Release { operation, .. },
            ) => expected == operation,
            _ => false,
        };
        let request_ok = matches!(self.grant, Grant::Inspect) || intent.request == self.request;
        if !allowed || !request_ok {
            return Err(Error::Denied);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Denied)?
            .as_secs();
        action(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActorId, PolicyRef};

    #[test]
    fn local_grant_rejects_another_actor_request_and_operation() {
        let context = Context {
            actor: ActorId([1; 32]),
            policy: PolicyRef([2; 32]),
        };
        let owner = Owner {
            vault: VaultId([3; 32]),
            context,
            request: RequestId([4; 32]),
            grant: Grant::Delete(SecretRef([5; 16]), 1),
        };
        let mut intent = Intent {
            vault: owner.vault,
            request: owner.request,
            context,
            binding: [0; 32],
            kind: IntentKind::Delete {
                secret: SecretRef([5; 16]),
                expected_version: 1,
            },
        };
        assert!(owner.with_authorization(&intent, |_| Ok(())).is_ok());
        intent.context.actor = ActorId([9; 32]);
        assert_eq!(
            owner.with_authorization(&intent, |_| Ok(())),
            Err(Error::Denied)
        );
        intent.context = context;
        intent.request = RequestId([9; 32]);
        assert_eq!(
            owner.with_authorization(&intent, |_| Ok(())),
            Err(Error::Denied)
        );
        intent.request = owner.request;
        intent.kind = IntentKind::Create;
        assert_eq!(
            owner.with_authorization(&intent, |_| Ok(())),
            Err(Error::Denied)
        );
        intent.kind = IntentKind::Delete {
            secret: SecretRef([5; 16]),
            expected_version: 2,
        };
        assert_eq!(
            owner.with_authorization(&intent, |_| Ok(())),
            Err(Error::Denied)
        );
    }
}
