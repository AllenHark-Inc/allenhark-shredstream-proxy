//! Raw shreds to entry batches: parse Merkle shreds off the wire, collect
//! them per slot and FEC set, recover missing data shreds from the coding
//! shreds (Reed-Solomon, the same code Agave uses), and hand back each
//! completed entry batch as the serialized `Vec<Entry>` bytes that
//! the entry decoders walk.
//!
//! Wire layout (Agave `ledger/src/shred.rs`, all shreds Merkle and chained):
//!
//! ```text
//! common header (83)  signature[64] variant u8  slot u64  index u32  version u16  fec_set_index u32
//! data header   (5)   parent_offset u16  flags u8  size u16          -> data = payload[88..size]
//! coding header (6)   num_data u16  num_coding u16  position u16    -> shard starts at 89
//! variant             0x6p code, 0x7p code (resigned), 0x9p data, 0xbp data (resigned); p = proof size
//! payload             data 1203 bytes, code 1228 bytes
//! ```
//!
//! An entry batch is the data of the data shreds from one batch start (index
//! 0, or the index after a shred flagged `DATA_COMPLETE`) to the next shred
//! flagged `DATA_COMPLETE`, concatenated (Agave `Shredder::deshred`). A batch
//! is handed back as soon as its shreds are all present, without waiting for
//! the rest of its FEC set.
//!
//! Erasure coding (Merkle shreds): a data shred's erasure shard is
//! `payload[64 .. 88 + capacity]` (its headers and data, not its signature);
//! a coding shred's is `payload[89 .. 89 + capacity]`. Both are the same
//! length. The shards of one FEC set are ordered data first (by index in the
//! set), then coding (by `position`).
//!
//! Nothing here checks signatures or Merkle proofs: the source is a trusted
//! shred feed. A malformed shred is counted and dropped.

use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SIZE_OF_SIGNATURE: usize = 64;
#[allow(dead_code)]
pub const SIZE_OF_COMMON_HEADER: usize = 83;
pub const SIZE_OF_DATA_HEADERS: usize = 88;
pub const SIZE_OF_CODING_HEADERS: usize = 89;
pub const DATA_PAYLOAD: usize = 1203;
pub const CODE_PAYLOAD: usize = 1228;
const SIZE_OF_MERKLE_ROOT: usize = 32;
const SIZE_OF_MERKLE_PROOF_ENTRY: usize = 20;

/// `flags` bits of a data shred.
pub const DATA_COMPLETE_SHRED: u8 = 0b0100_0000;
pub const LAST_SHRED_IN_SLOT: u8 = 0b1100_0000;

/// Most data or coding shreds in one FEC set that we accept.
const MAX_SHREDS_PER_SET: u16 = 256;
/// Highest data shred index we accept (Agave's per-slot maximum).
const MAX_DATA_INDEX: u32 = 32_768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredKind {
    Data {
        parent_offset: u16,
        flags: u8,
        /// Headers plus data: the data is `payload[88..size]`.
        size: u16,
    },
    Code {
        num_data: u16,
        num_coding: u16,
        position: u16,
    },
}

/// One parsed shred, borrowing the packet.
#[derive(Debug, Clone, Copy)]
pub struct Shred<'a> {
    pub slot: u64,
    pub index: u32,
    #[allow(dead_code)]
    pub version: u16,
    pub fec_set_index: u32,
    pub proof_size: u8,
    pub resigned: bool,
    pub kind: ShredKind,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredError {
    /// Shorter than its payload size, or not a shred at all.
    Size,
    /// Legacy or unknown variant byte.
    Variant,
    /// A header field out of range.
    Header,
}

fn u16_at(p: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([p[o], p[o + 1]])
}
fn u32_at(p: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(p[o..o + 4].try_into().expect("4"))
}
fn u64_at(p: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(p[o..o + 8].try_into().expect("8"))
}

/// Data bytes a data shred can carry.
pub fn data_capacity(proof_size: u8, resigned: bool) -> Option<usize> {
    DATA_PAYLOAD.checked_sub(
        SIZE_OF_DATA_HEADERS
            + SIZE_OF_MERKLE_ROOT
            + usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY
            + if resigned { SIZE_OF_SIGNATURE } else { 0 },
    )
}

/// Length of the erasure shard (the same for data and coding shreds).
pub fn shard_len(proof_size: u8, resigned: bool) -> Option<usize> {
    data_capacity(proof_size, resigned).map(|c| SIZE_OF_DATA_HEADERS + c - SIZE_OF_SIGNATURE)
}

/// Parse a shred off the wire (`packet` may carry trailing bytes, e.g. a
/// repair nonce; they are ignored).
pub fn parse(packet: &[u8]) -> Result<Shred<'_>, ShredError> {
    if packet.len() < SIZE_OF_CODING_HEADERS {
        return Err(ShredError::Size);
    }
    let variant = packet[SIZE_OF_SIGNATURE];
    let proof_size = variant & 0x0f;
    let (is_data, resigned) = match variant & 0xf0 {
        0x60 => (false, false),
        0x70 => (false, true),
        0x90 => (true, false),
        0xb0 => (true, true),
        _ => return Err(ShredError::Variant),
    };
    let need = if is_data { DATA_PAYLOAD } else { CODE_PAYLOAD };
    if packet.len() < need {
        return Err(ShredError::Size);
    }
    let payload = &packet[..need];
    let cap = data_capacity(proof_size, resigned).ok_or(ShredError::Header)?;
    let slot = u64_at(payload, 65);
    let index = u32_at(payload, 73);
    let version = u16_at(payload, 77);
    let fec_set_index = u32_at(payload, 79);
    let kind = if is_data {
        let parent_offset = u16_at(payload, 83);
        let flags = payload[85];
        let size = u16_at(payload, 86);
        let s = usize::from(size);
        if !(SIZE_OF_DATA_HEADERS..=SIZE_OF_DATA_HEADERS + cap).contains(&s)
            || index < fec_set_index
            || index - fec_set_index >= u32::from(MAX_SHREDS_PER_SET)
            || index > MAX_DATA_INDEX
        {
            return Err(ShredError::Header);
        }
        ShredKind::Data {
            parent_offset,
            flags,
            size,
        }
    } else {
        let num_data = u16_at(payload, 83);
        let num_coding = u16_at(payload, 85);
        let position = u16_at(payload, 87);
        if num_data == 0
            || num_coding == 0
            || num_data > MAX_SHREDS_PER_SET
            || num_coding > MAX_SHREDS_PER_SET
            || position >= num_coding
        {
            return Err(ShredError::Header);
        }
        ShredKind::Code {
            num_data,
            num_coding,
            position,
        }
    };
    Ok(Shred {
        slot,
        index,
        version,
        fec_set_index,
        proof_size,
        resigned,
        kind,
        payload,
    })
}

impl Shred<'_> {
    /// A data shred's entry bytes.
    pub fn data(&self) -> Option<&[u8]> {
        match self.kind {
            ShredKind::Data { size, .. } => {
                Some(&self.payload[SIZE_OF_DATA_HEADERS..usize::from(size)])
            }
            ShredKind::Code { .. } => None,
        }
    }

    /// The erasure-coded slice.
    pub fn erasure_shard(&self) -> Option<&[u8]> {
        let len = shard_len(self.proof_size, self.resigned)?;
        let start = match self.kind {
            ShredKind::Data { .. } => SIZE_OF_SIGNATURE,
            ShredKind::Code { .. } => SIZE_OF_CODING_HEADERS,
        };
        self.payload.get(start..start + len)
    }
}

/// Counters for the deshredder (all cumulative).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeshredStats {
    pub shreds: u64,
    pub data_shreds: u64,
    pub code_shreds: u64,
    pub bad_shreds: u64,
    pub duplicate_shreds: u64,
    /// Shreds for a slot already finished or too old.
    pub late_shreds: u64,
    /// Data shreds rebuilt from coding shreds: lost ones, and late ones
    /// (recovery runs as soon as a set has enough shreds).
    pub recovered_data_shreds: u64,
    pub recovery_failures: u64,
    pub batches: u64,
    pub batch_bytes: u64,
    /// Slots dropped while they still had batches that never completed.
    pub incomplete_slots: u64,
}

/// One completed entry batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryBatch {
    pub slot: u64,
    /// Index of its first data shred.
    pub start_index: u32,
    /// Index of its last data shred (the one flagged `DATA_COMPLETE`).
    pub end_index: u32,
    /// Serialized `Vec<Entry>`.
    pub bytes: Vec<u8>,
    /// Some of its shreds were recovered from coding shreds.
    pub recovered: bool,
}

struct DataShred {
    data: Vec<u8>,
    recovered: bool,
}

#[derive(Default)]
struct FecSet {
    /// From the first coding shred.
    num_data: u16,
    num_coding: u16,
    proof_size: u8,
    resigned: bool,
    /// Erasure shards by position in the set (data: index - fec_set_index).
    data_shards: BTreeMap<u16, Vec<u8>>,
    code_shards: BTreeMap<u16, Vec<u8>>,
    /// All data shreds present (received or recovered): nothing more to do.
    done: bool,
}

struct SlotState {
    data: BTreeMap<u32, DataShred>,
    /// Indexes of shreds flagged `DATA_COMPLETE`.
    completes: BTreeSet<u32>,
    /// Batch starts known and not yet handed back.
    starts: BTreeSet<u32>,
    sets: HashMap<u32, FecSet>,
    /// The last batch (the slot's last shred) was handed back.
    finished: bool,
}

impl Default for SlotState {
    /// A new slot: its first batch starts at index 0.
    fn default() -> Self {
        Self {
            data: BTreeMap::new(),
            completes: BTreeSet::new(),
            starts: BTreeSet::from([0]),
            sets: HashMap::new(),
            finished: false,
        }
    }
}

/// Collects shreds and hands back completed entry batches.
pub struct Deshredder {
    slots: BTreeMap<u64, SlotState>,
    /// Slots more than this far behind the highest one seen are dropped.
    keep_slots: u64,
    highest: u64,
    pub stats: DeshredStats,
    codecs: HashMap<(u16, u16), ReedSolomon>,
}

impl Default for Deshredder {
    fn default() -> Self {
        Self::new(32)
    }
}

impl Deshredder {
    pub fn new(keep_slots: u64) -> Self {
        Self {
            slots: BTreeMap::new(),
            keep_slots: keep_slots.max(2),
            highest: 0,
            stats: DeshredStats::default(),
            codecs: HashMap::new(),
        }
    }

    /// Slots currently held.
    #[allow(dead_code)]
    pub fn slots_held(&self) -> usize {
        self.slots.len()
    }

    /// Feed one packet; returns the entry batches it completed (in order).
    pub fn push(&mut self, packet: &[u8]) -> Vec<EntryBatch> {
        self.stats.shreds += 1;
        let shred = match parse(packet) {
            Ok(s) => s,
            Err(_) => {
                self.stats.bad_shreds += 1;
                return Vec::new();
            }
        };
        let slot = shred.slot;
        if slot + self.keep_slots < self.highest {
            self.stats.late_shreds += 1;
            return Vec::new();
        }
        if slot > self.highest {
            self.highest = slot;
            self.evict();
        }
        let st = self.slots.entry(slot).or_default();
        if st.finished {
            self.stats.late_shreds += 1;
            return Vec::new();
        }
        let set_key = shred.fec_set_index;
        let mut touched = false;
        match shred.kind {
            ShredKind::Data { flags, .. } => {
                self.stats.data_shreds += 1;
                if st.data.contains_key(&shred.index) {
                    self.stats.duplicate_shreds += 1;
                    return Vec::new();
                }
                let set = st.sets.entry(set_key).or_default();
                if !set.done {
                    if let Some(sh) = shred.erasure_shard() {
                        let pos = (shred.index - set_key) as u16;
                        set.data_shards.insert(pos, sh.to_vec());
                        set.proof_size = shred.proof_size;
                        set.resigned = shred.resigned;
                    }
                }
                insert_data(
                    st,
                    shred.index,
                    flags,
                    shred.data().unwrap_or_default().to_vec(),
                    false,
                );
                touched = true;
            }
            ShredKind::Code {
                num_data,
                num_coding,
                position,
            } => {
                self.stats.code_shreds += 1;
                let set = st.sets.entry(set_key).or_default();
                if set.done {
                    return Vec::new();
                }
                if set.num_data == 0 {
                    set.num_data = num_data;
                    set.num_coding = num_coding;
                    set.proof_size = shred.proof_size;
                    set.resigned = shred.resigned;
                } else if set.num_data != num_data || set.num_coding != num_coding {
                    self.stats.bad_shreds += 1;
                    return Vec::new();
                }
                if set.code_shards.contains_key(&position) {
                    self.stats.duplicate_shreds += 1;
                    return Vec::new();
                }
                if let Some(sh) = shred.erasure_shard() {
                    set.code_shards.insert(position, sh.to_vec());
                }
            }
        }
        // Recover the set if it can be and needs it.
        let set = st.sets.get_mut(&set_key).expect("set");
        if !set.done && set.num_data > 0 {
            let have = set.data_shards.len();
            let nd = usize::from(set.num_data);
            if have >= nd {
                set.done = true;
                set.data_shards.clear();
                set.code_shards.clear();
            } else if have + set.code_shards.len() >= nd {
                match recover(&mut self.codecs, slot, set_key, set) {
                    Ok(rec) => {
                        for (index, flags, data) in rec {
                            if !st.data.contains_key(&index) {
                                self.stats.recovered_data_shreds += 1;
                                insert_data(st, index, flags, data, true);
                                touched = true;
                            }
                        }
                    }
                    Err(()) => self.stats.recovery_failures += 1,
                }
                let set = st.sets.get_mut(&set_key).expect("set");
                set.done = true;
                set.data_shards.clear();
                set.code_shards.clear();
            }
        }
        if !touched {
            return Vec::new();
        }
        let out = drain(slot, st);
        for b in &out {
            self.stats.batches += 1;
            self.stats.batch_bytes += b.bytes.len() as u64;
        }
        out
    }

    fn evict(&mut self) {
        let floor = self.highest.saturating_sub(self.keep_slots);
        while let Some((&s, _)) = self.slots.first_key_value() {
            if s >= floor {
                break;
            }
            let st = self.slots.remove(&s).expect("slot");
            if !st.finished && !st.starts.is_empty() {
                self.stats.incomplete_slots += 1;
            }
        }
    }
}

fn insert_data(st: &mut SlotState, index: u32, flags: u8, data: Vec<u8>, recovered: bool) {
    if flags & DATA_COMPLETE_SHRED != 0 {
        st.completes.insert(index);
        if flags & LAST_SHRED_IN_SLOT != LAST_SHRED_IN_SLOT {
            st.starts.insert(index + 1);
        }
    }
    st.data.insert(index, DataShred { data, recovered });
}

/// Hand back every batch whose shreds are all present.
fn drain(slot: u64, st: &mut SlotState) -> Vec<EntryBatch> {
    let mut out = Vec::new();
    let starts: Vec<u32> = st.starts.iter().copied().collect();
    for s in starts {
        let Some(&e) = st.completes.range(s..).next() else {
            continue;
        };
        let n = st.data.range(s..=e).count();
        if n as u64 != u64::from(e - s) + 1 {
            continue;
        }
        let mut bytes = Vec::with_capacity(n * 1100);
        let mut recovered = false;
        for d in st.data.range(s..=e).map(|(_, d)| d) {
            bytes.extend_from_slice(&d.data);
            recovered |= d.recovered;
        }
        st.starts.remove(&s);
        // The data is no longer needed; keep the keys for duplicate checks.
        for (_, d) in st.data.range_mut(s..=e) {
            d.data = Vec::new();
        }
        out.push(EntryBatch {
            slot,
            start_index: s,
            end_index: e,
            bytes,
            recovered,
        });
    }
    // Every batch but the slot's last adds the next start, so no start left
    // means the slot's last batch was handed back.
    if st.starts.is_empty() {
        st.finished = true;
        st.sets.clear();
    }
    out
}

type Recovered = Vec<(u32, u8, Vec<u8>)>;

/// Reed-Solomon recovery of the missing data shreds of a set.
fn recover(
    codecs: &mut HashMap<(u16, u16), ReedSolomon>,
    slot: u64,
    fec_set_index: u32,
    set: &FecSet,
) -> Result<Recovered, ()> {
    let nd = usize::from(set.num_data);
    let nc = usize::from(set.num_coding);
    let len = shard_len(set.proof_size, set.resigned).ok_or(())?;
    let rs = match codecs.entry((set.num_data, set.num_coding)) {
        std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
        std::collections::hash_map::Entry::Vacant(v) => {
            v.insert(ReedSolomon::new(nd, nc).map_err(|_| ())?)
        }
    };
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; nd + nc];
    for (&p, s) in &set.data_shards {
        if usize::from(p) < nd && s.len() == len {
            shards[usize::from(p)] = Some(s.clone());
        }
    }
    for (&p, s) in &set.code_shards {
        if usize::from(p) < nc && s.len() == len {
            shards[nd + usize::from(p)] = Some(s.clone());
        }
    }
    let missing: Vec<usize> = (0..nd).filter(|&i| shards[i].is_none()).collect();
    rs.reconstruct_data(&mut shards).map_err(|_| ())?;
    let mut out = Vec::with_capacity(missing.len());
    for i in missing {
        let sh = shards[i].as_ref().ok_or(())?;
        // The shard is the payload without its signature.
        let base = SIZE_OF_SIGNATURE;
        let at = |o: usize| o - base;
        let variant = sh[at(64)];
        if variant & 0xf0 != 0x90 && variant & 0xf0 != 0xb0 {
            return Err(());
        }
        let s = u64_at(sh, at(65));
        let index = u32_at(sh, at(73));
        let fec = u32_at(sh, at(79));
        if s != slot || fec != fec_set_index || index != fec_set_index + i as u32 {
            return Err(());
        }
        let flags = sh[at(85)];
        let size = usize::from(u16_at(sh, at(86)));
        let cap = data_capacity(set.proof_size, set.resigned).ok_or(())?;
        if !(SIZE_OF_DATA_HEADERS..=SIZE_OF_DATA_HEADERS + cap).contains(&size) {
            return Err(());
        }
        out.push((
            index,
            flags,
            sh[at(SIZE_OF_DATA_HEADERS)..at(size)].to_vec(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A data shred with `data`, built the way Agave lays it out.
    pub(crate) fn data_shred(slot: u64, index: u32, fec: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; DATA_PAYLOAD];
        p[64] = 0x90 | 6;
        p[65..73].copy_from_slice(&slot.to_le_bytes());
        p[73..77].copy_from_slice(&index.to_le_bytes());
        p[79..83].copy_from_slice(&fec.to_le_bytes());
        p[83..85].copy_from_slice(&1u16.to_le_bytes());
        p[85] = flags;
        let size = (SIZE_OF_DATA_HEADERS + data.len()) as u16;
        p[86..88].copy_from_slice(&size.to_le_bytes());
        p[88..88 + data.len()].copy_from_slice(data);
        p
    }

    #[test]
    fn parses_headers_and_rejects_garbage() {
        let p = data_shred(7, 3, 0, DATA_COMPLETE_SHRED, b"abc");
        let s = parse(&p).unwrap();
        assert_eq!(
            (s.slot, s.index, s.fec_set_index, s.proof_size),
            (7, 3, 0, 6)
        );
        assert_eq!(s.data().unwrap(), b"abc");
        assert_eq!(
            s.erasure_shard().unwrap().len(),
            shard_len(6, false).unwrap()
        );
        assert_eq!(parse(&p[..100]).unwrap_err(), ShredError::Size);
        let mut legacy = p.clone();
        legacy[64] = 0xa5;
        assert_eq!(parse(&legacy).unwrap_err(), ShredError::Variant);
        let mut big = p.clone();
        big[86..88].copy_from_slice(&2000u16.to_le_bytes());
        assert_eq!(parse(&big).unwrap_err(), ShredError::Header);
    }

    #[test]
    fn batches_complete_in_any_order() {
        let mut d = Deshredder::new(8);
        let a = data_shred(5, 0, 0, 0, b"he");
        let b = data_shred(5, 1, 0, DATA_COMPLETE_SHRED, b"llo");
        let c = data_shred(5, 2, 0, LAST_SHRED_IN_SLOT, b"!");
        // c alone is a whole batch only once its start (2) is known.
        assert!(d.push(&c).is_empty());
        let got = |v: Vec<EntryBatch>| -> Vec<(u32, Vec<u8>)> {
            v.into_iter().map(|b| (b.start_index, b.bytes)).collect()
        };
        assert_eq!(got(d.push(&b)), vec![(2, b"!".to_vec())]);
        assert_eq!(got(d.push(&a)), vec![(0, b"hello".to_vec())]);
        // Finished: late copies are ignored.
        assert!(d.push(&a).is_empty());
        assert_eq!(d.stats.batches, 2);
    }

    #[test]
    fn old_slots_are_dropped() {
        let mut d = Deshredder::new(4);
        d.push(&data_shred(1, 0, 0, 0, b"x"));
        d.push(&data_shred(10, 0, 0, 0, b"x"));
        assert_eq!(d.slots_held(), 1);
        assert_eq!(d.stats.incomplete_slots, 1);
        assert!(d
            .push(&data_shred(2, 1, 0, DATA_COMPLETE_SHRED, b"y"))
            .is_empty());
        assert_eq!(d.stats.late_shreds, 1);
    }
}
