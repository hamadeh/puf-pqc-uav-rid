# Updated-protocol alignment and manuscript impact

## Implemented code changes

1. Replaced the two independent emulated PUF channels with one
   `PUF.Enroll(CSeed)` / `PUF.Reconstruct(CSeed,HD)` source. `S1` and `S2` are
   purpose-separated with SHAKE256 labels `PUF-SIGN` and `PUF-MERKLE`.
2. Implemented top-950 response selection at the fixed 0.5% enrollment-margin
   threshold, shortened BCH(950,870) with correction capacity `t=8`, code-offset
   helper data, and a 950-to-256-bit seeded Toeplitz extractor.
3. Added strict protocol-v1 binary objects with fixed-width network-order
   integers, ordered TLV fields, explicit type/version headers, and rejection
   of duplicate, unknown, malformed, or trailing data.
4. Changed Merkle internal-node separation to `0x01`, retained leaf separation
   `0x00`, required power-of-two trees, and bound each proof to explicit
   direction bits and exactly `log2(n)` entries.
5. Added fresh TA challenges and direct ML-DSA proof of possession to UAV root
   enrollment and verifier enrollment. The TA now checks device authorization,
   nonce freshness/reuse, root-index reuse, context policy, and stable renewal
   keys before signing.
6. Added renewal using the existing PUF helper and key-confirmation value. The
   TA commits the legal key binding only after the first valid proof of
   possession.
7. Added signed, versioned revocation-list records and `CertID`, `RootID`, and
   `KeyID` checks at activation, UAV admission, and verifier acceptance.
8. Removed the interval journal from the active protocol. The interval index is
   `j = 1 + floor((TS-StartTime)/DeltaT)` and is checked against root validity.
9. Changed the public Profile-P identifier to exactly 20 bytes:
   `SSIType || PID(16 bytes) || 0x000000`; it exposes neither `k` nor `j`.
10. Replaced subprocess-per-request TCP processing with one resident UAV
    service that validates and builds the active tree once at startup.
11. Added bounded request size, global and per-certificate token buckets,
    certificate/pseudonym request spacing, atomic replay consumption, bounded
    concurrent work, queue-time freshness rechecks, and trusted-time rollback
    detection.
12. Corrected request and response signing to sign canonical objects directly.
    Corrected `ReqID`, deterministic AEAD nonce, session-key KDF, transcript,
    encrypted payload, and associated-data field sets to the revised
    Algorithms 5 and 6.
13. Serialized liboqs's process-global deterministic-randomness override so
    concurrent seeded ML-DSA regeneration cannot corrupt another request.
14. Added dependency-light regression tests for the shortened BCH, one-PUF
    helper path, canonical decoder, Merkle proof binding, and replay state.

## Manuscript text and results requiring modification or rerun

- Replace every description of two PUF/FE channels (`CSeed1/HD1` and
  `CSeed2/HD2`, or separate “S1/S2 reconstruction channels”) with one
  `CSeed/HD/K_PUF` followed by purpose-separated `S1` and `S2`.
- Replace BCH(1023,943,17), BCH(1023,936), or byte-aligned-capacity wording in
  the active protocol with shortened BCH(950,870), minimum distance 17,
  correction capacity `t=8`.
- State that the 1023 candidate comparisons are reduced to the top 950 that
  satisfy the fixed 0.5% normalized-margin rule. Conditional entropy claims
  must account for the public selection mask and all helper data.
- Replace JSON-as-wire-format statements with: JSON is only local/file-channel
  storage; cryptographic request, certificate, authorization, revocation,
  payload, and response objects use strict canonical binary encoding.
- Remove active-protocol claims about two-slot interval journals, durable
  pseudonym reservation, consumed indices, and crash-recovery latency. They
  describe a superseded design and are not evidence for the revised
  time-derived-slot protocol.
- Add TA challenge freshness, UAV root-request proof of possession, verifier
  enrollment proof of possession, root-index uniqueness, stable renewal key,
  and delayed legal key-binding checks to the enrollment description.
- Add versioned signed revocation-list distribution and fail-closed
  `CertID`/`RootID`/`KeyID` checks to activation and authentication text.
- State that broadcasts contain only the 20-byte Profile-P UAS ID and do not
  reveal a root or interval index.
- State that the live UAV service retains only active volatile tree/index
  state; root activation is not repeated inside each timed TCP request.
- Update request/response field listings, byte counts, packet counts, and
  fragmentation calculations because canonical binary serialization and the
  reduced encrypted payload change both messages.
- For the current fixed algorithms and the repository's verifier identity
  strings, canonical structural sizes are: signed request 10,030 bytes;
  response 5,095 bytes at `n=1024` (10-node path); and response 5,291 bytes at
  `n=16384` (14-node path). With this TCP harness's framing, the corresponding
  application-byte counts are 10,038 bytes request and 5,111/5,307 bytes
  response. These are deterministic encoded sizes, not latency or radio
  measurements; confirm them in the rerun CSV before publication.
- Additional deterministic sizes from the corrected codec are: 20-byte
  broadcast UAS ID; 492/688-byte encoded Merkle path for `n=1024/16384`;
  5,481-byte root authorization record; 5,404-byte verifier certificate;
  3,403-byte empty signed revocation record; and 9,375-byte local JSON helper
  representation. The active interval-journal size is zero. Local JSON size
  is implementation-format dependent and should be labeled accordingly.
- The Raspberry Pi software-latency rerun is complete for PUF reconstruction,
  Merkle-root generation, pre-flight activation, and UAV on-demand
  authentication at `n=1024` and `n=16384`, with one discarded warm-up and 30
  recorded trials per operation. The curated evidence is under
  `Results/protocol_v1_20260724/table12_pi/`.
- The live Wi-Fi/TCP rerun is complete for both sizes. All 60 recorded
  exchanges were cryptographically accepted. The curated CSV/JSON/PCAP
  evidence, packet filters, and interpretation boundaries are under
  `Results/protocol_v1_20260724/table13_live/`.
- Do not reuse the existing live RTT values (including the previously observed
  `n=16384` mean of 1494.865 ms) as revised-protocol results.
- Updated deterministic protocol-v1 object sizes are included in the Raspberry
  Pi result JSON. The active design has one PUF helper, no interval journal,
  and signed authorization, certificate, and revocation records.
- Updated Tamarin core and revocation models and their verification logs are
  under `Tamarin/Tamarin_Final_Evidence/`.
- LTspice population, PVT, uniqueness, uniformity, bit-alias, entropy, BER, and
  decoder-failure results do not change merely because Python serialization or
  enrollment messages changed. They must be recomputed only if the LTspice
  analysis did not apply the same 1023-candidate/top-950/0.5%-margin and
  BCH(950,870), `t=8` policy.

Historical CSV/JSON/PCAP files remain labeled “pre-alignment implementation”;
they have not been overwritten or relabeled.
