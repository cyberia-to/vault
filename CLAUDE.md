# vault — secret custody, durable storage and private synchronization

This repository owns Vault's product, secret schemas, custody operations,
encrypted-record semantics, synchronization rules and recovery contract.
README.md is the product entry; specs/README.md indexes the contracts.

- This is a specifications-first repository. Do not describe sketches as
  implemented APIs or add placeholder runtime crates as evidence of readiness.
- Keep specifications in English. Implementation reviews, measurements and
  release evidence belong in audit/, not specs/.
- Preserve `derive_neuron`, existing identity/derivation/signature bytes and
  native/foreign subject distinctions. Vault references are not new subjects.
- Ward owns permission; Mudra owns crypto; Cybergraph owns history; BBG owns
  physical durability; existing stack components own transport and consensus.
  Do not create competing permission, database or synchronization engines.
- Never inspect or import real user secrets for development. Use synthetic
  fixtures. No seed, key, password, token, plaintext database or recovery kit
  belongs in Git, logs, command arguments or model context.
- Local durability, replica acknowledgement, current availability and recovery
  freshness are distinct claims. Pin the evidence and revision for each claim.
- A proposed stronger guarantee needs an explicit profile and acceptance gate.
  No secret export or weaker custody fallback to make an operation succeed.
