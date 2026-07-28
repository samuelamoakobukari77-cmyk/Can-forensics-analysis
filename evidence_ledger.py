"""
evidence_ledger.py

Chain-of-custody evidence integrity module for the CAN Bus Forensic
Analysis capstone project.

Two complementary integrity mechanisms are provided, matching what
digital-forensics chain-of-custody systems typically use:

1. HASH CHAIN (blockchain-style linked list)
   Every evidence record stores the SHA-256 hash of the *previous*
   record alongside its own data hash. This means tampering with any
   single record breaks the chain from that point forward, and the
   break is trivially detectable.

2. MERKLE TREE (batch integrity + efficient proofs)
   For a batch of records (e.g. all packets flagged as part of one
   detected attack window), a Merkle tree lets you:
   - Produce a single root hash that "fingerprints" the whole batch
   - Prove that one specific record belongs to that batch without
     revealing/re-hashing all the other records (a Merkle proof)

Together these give you a defensible, presentable answer to
"how do you know this evidence wasn't altered after capture?" --
which is exactly the kind of thing that makes a forensics tool
prize-worthy rather than "basic".

No external dependencies beyond the Python standard library.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON serialization so the same logical data always
    hashes to the same value regardless of dict key ordering.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


GENESIS_HASH = "0" * 64  # hash of "nothing came before this"


# --------------------------------------------------------------------------
# Hash chain
# --------------------------------------------------------------------------

@dataclass
class LedgerRecord:
    index: int
    timestamp: float
    event_type: str          # e.g. "capture", "detection", "export", "annotation"
    data: dict               # the actual evidence payload (packet info, detection result, etc.)
    data_hash: str            # sha256 of `data` alone
    prev_hash: str            # hash of the previous record's block
    record_hash: str          # sha256 of (index + timestamp + event_type + data_hash + prev_hash)

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceLedger:
    """
    An append-only, tamper-evident log of forensic evidence events.

    Usage:
        ledger = EvidenceLedger(case_id="INC-2026-0042")
        ledger.add_record("detection", {"can_id": "0x123", "label": "DoS", "confidence": 0.97})
        ledger.add_record("export", {"report_file": "report.pdf"})
        ok, problem = ledger.verify_chain()
    """

    def __init__(self, case_id: str = "default-case"):
        self.case_id = case_id
        self._records: list[LedgerRecord] = []

    # ---- writing -------------------------------------------------------

    def add_record(self, event_type: str, data: dict, timestamp: Optional[float] = None) -> LedgerRecord:
        idx = len(self._records)
        ts = timestamp if timestamp is not None else time.time()
        prev_hash = self._records[-1].record_hash if self._records else GENESIS_HASH

        data_hash = sha256_hex(canonical_json(data))

        block_payload = {
            "index": idx,
            "timestamp": ts,
            "event_type": event_type,
            "data_hash": data_hash,
            "prev_hash": prev_hash,
        }
        record_hash = sha256_hex(canonical_json(block_payload))

        record = LedgerRecord(
            index=idx,
            timestamp=ts,
            event_type=event_type,
            data=data,
            data_hash=data_hash,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )
        self._records.append(record)
        return record

    # ---- reading --------------------------------------------------------

    @property
    def records(self) -> list[LedgerRecord]:
        return list(self._records)

    def to_json(self) -> str:
        return json.dumps(
            {
                "case_id": self.case_id,
                "records": [r.to_dict() for r in self._records],
            },
            indent=2,
            default=str,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "EvidenceLedger":
        payload = json.loads(json_str)
        ledger = cls(case_id=payload.get("case_id", "default-case"))
        for r in payload["records"]:
            record = LedgerRecord(
                index=r["index"],
                timestamp=r["timestamp"],
                event_type=r["event_type"],
                data=r["data"],
                data_hash=r["data_hash"],
                prev_hash=r["prev_hash"],
                record_hash=r["record_hash"],
            )
            ledger._records.append(record)
        return ledger

    # ---- verification ----------------------------------------------------

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """
        Re-derives every hash from scratch and checks it against what's
        stored. Returns (True, None) if the whole chain is intact, or
        (False, "human-readable problem description") at the first break.
        """
        expected_prev = GENESIS_HASH

        for r in self._records:
            # 1. Does the data still hash to what was recorded?
            recomputed_data_hash = sha256_hex(canonical_json(r.data))
            if recomputed_data_hash != r.data_hash:
                return False, f"Record {r.index}: evidence data was modified (data hash mismatch)."

            # 2. Does this record correctly point at the previous one?
            if r.prev_hash != expected_prev:
                return False, f"Record {r.index}: chain link broken (prev_hash does not match record {r.index - 1})."

            # 3. Does the record's own hash still check out?
            block_payload = {
                "index": r.index,
                "timestamp": r.timestamp,
                "event_type": r.event_type,
                "data_hash": r.data_hash,
                "prev_hash": r.prev_hash,
            }
            recomputed_record_hash = sha256_hex(canonical_json(block_payload))
            if recomputed_record_hash != r.record_hash:
                return False, f"Record {r.index}: record hash mismatch (metadata was altered)."

            expected_prev = r.record_hash

        return True, None

    def tamper_demo(self, index: int, new_data: dict) -> None:
        """
        FOR DEMO/TESTING ONLY: deliberately corrupts a record's data
        without recomputing hashes, so you can show verify_chain()
        catching it live during your defense/demo.
        """
        self._records[index].data = new_data


# --------------------------------------------------------------------------
# Merkle tree (for batching e.g. all packets in one detected attack window)
# --------------------------------------------------------------------------

class MerkleTree:
    """
    Standard binary Merkle tree over a list of leaf items (dicts or strings).
    Odd leaf counts are handled by duplicating the last leaf, which is the
    common convention (as used in Bitcoin's implementation).
    """

    def __init__(self, leaves: list[Any]):
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf")
        self.leaf_hashes = [sha256_hex(canonical_json(leaf)) for leaf in leaves]
        self.levels: list[list[str]] = [self.leaf_hashes]
        self._build()

    def _build(self) -> None:
        current = self.levels[0]
        while len(current) > 1:
            if len(current) % 2 == 1:
                current = current + [current[-1]]
            next_level = [
                sha256_hex((current[i] + current[i + 1]).encode("utf-8"))
                for i in range(0, len(current), 2)
            ]
            self.levels.append(next_level)
            current = next_level

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def get_proof(self, leaf_index: int) -> list[dict]:
        """
        Returns the sibling hashes needed to prove that the leaf at
        leaf_index is part of the tree that produced self.root.
        Each proof step is {"hash": ..., "position": "left"|"right"}.
        """
        proof = []
        idx = leaf_index
        for level in self.levels[:-1]:
            level_padded = level if len(level) % 2 == 0 else level + [level[-1]]
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            position = "right" if idx % 2 == 0 else "left"
            proof.append({"hash": level_padded[sibling_idx], "position": position})
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf: Any, proof: list[dict], root: str) -> bool:
        current_hash = sha256_hex(canonical_json(leaf))
        for step in proof:
            if step["position"] == "right":
                current_hash = sha256_hex((current_hash + step["hash"]).encode("utf-8"))
            else:
                current_hash = sha256_hex((step["hash"] + current_hash).encode("utf-8"))
        return current_hash == root


# --------------------------------------------------------------------------
# Self-test / demo when run directly: `python evidence_ledger.py`
# --------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Hash Chain Demo ===")
    ledger = EvidenceLedger(case_id="DEMO-CASE-001")
    ledger.add_record("capture", {"can_id": "0x0316", "dlc": 8, "data": "00 FF 00 00 00 00 00 52"})
    ledger.add_record("detection", {"can_id": "0x0316", "label": "DoS", "confidence": 0.982})
    ledger.add_record("export", {"report_file": "incident_report_2026-07-24.pdf", "hash": "abc123"})

    ok, problem = ledger.verify_chain()
    print(f"Chain intact? {ok}")

    print("\n--- Now tampering with record 1 (changing the detection label) ---")
    ledger.tamper_demo(1, {"can_id": "0x0316", "label": "Normal", "confidence": 0.982})
    ok, problem = ledger.verify_chain()
    print(f"Chain intact? {ok}")
    print(f"Problem detected: {problem}")

    print("\n=== Merkle Tree Demo ===")
    packets = [
        {"can_id": "0x0316", "ts": 100.001},
        {"can_id": "0x0316", "ts": 100.002},
        {"can_id": "0x0320", "ts": 100.003},
        {"can_id": "0x0316", "ts": 100.004},
        {"can_id": "0x0430", "ts": 100.005},
    ]
    tree = MerkleTree(packets)
    print(f"Merkle root for attack-window batch of {len(packets)} packets: {tree.root}")

    proof = tree.get_proof(2)
    is_valid = MerkleTree.verify_proof(packets[2], proof, tree.root)
    print(f"Proof that packet #2 belongs to this batch, without re-hashing all packets: {is_valid}")
