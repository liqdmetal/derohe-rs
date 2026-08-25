//! graviton — DERO's merkleized key-value state tree — mirrors
//! github.com/deroproject/graviton (the balance tree, SC data trees, and the
//! version root all use this).
//!
//! Structure: a binary trie over the BLAKE2s-256 hash of each key (bit 0 =
//! MSB of byte 0). Every leaf's hash is blake2s(2 ‖ blake2s(key) ‖
//! blake2s(value)); every inner node's hash is blake2s(1 ‖ lhash ‖ rhash)
//! with empty children hashing as 32 zero bytes. The tree root is ALWAYS an
//! inner node (Go: `root: *inner`), so even the empty tree hashes as
//! inner(zeros, zeros).
//!
//! Clean-room: written from the reference source, not copied.

use blake2::Blake2s256;
use blake2::Digest;

pub const HASHSIZE: usize = 32;
pub const MAX_VALUE_SIZE: usize = 100 * 1024 * 1024;

const NULL_NODE: u8 = 0;
const INNER_NODE: u8 = 1;
const LEAF_NODE: u8 = 2;

/// BLAKE2s-256 over the given bytes.
pub fn grav_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let h = Blake2s256::digest(data);
    out.copy_from_slice(&h);
    out
}

/// sum(key) — the key hash used to address the trie.
pub fn sum(key: &[u8]) -> [u8; 32] {
    grav_hash(key)
}

/// The "empty child" hash. Go's init() computes this as
/// blake2s(leafNODE ‖ 32 zero bytes) and stores it in the zerosHash global —
/// NOT 32 zero bytes.
pub fn zeros_hash() -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[0] = LEAF_NODE;
    grav_hash(&buf)
}

/// Leaf hash: blake2s(2 ‖ blake2s(key) ‖ blake2s(value)).
pub fn leaf_hash(keyhash: &[u8], hvalue: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 32 + 32);
    buf.push(LEAF_NODE);
    buf.extend_from_slice(keyhash);
    buf.extend_from_slice(hvalue);
    grav_hash(&buf)
}

/// Inner hash: blake2s(1 ‖ lhash ‖ rhash).
pub fn inner_hash(lhash: &[u8], rhash: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 32 + 32);
    buf.push(INNER_NODE);
    buf.extend_from_slice(lhash);
    buf.extend_from_slice(rhash);
    grav_hash(&buf)
}

/// The bit-trie node.
#[derive(Clone, Debug)]
pub enum Node {
    Leaf { keyhash: [u8; 32], key: Vec<u8>, value: Vec<u8> },
    Inner { bit: u8, left: Option<Box<Node>>, right: Option<Box<Node>> },
}

impl Node {
    pub fn hash(&self) -> [u8; 32] {
        match self {
            Node::Leaf { keyhash, value, .. } => {
                let hval = grav_hash(value);
                leaf_hash(keyhash, &hval)
            }
            Node::Inner { bit: _, left, right } => {
                let z = zeros_hash();
                let lh = match left {
                    Some(l) => l.hash(),
                    None => z,
                };
                let rh = match right {
                    Some(r) => r.hash(),
                    None => z,
                };
                inner_hash(&lh, &rh)
            }
        }
    }

    fn left_mut(&mut self) -> &mut Option<Box<Node>> {
        match self {
            Node::Inner { left, .. } => left,
            _ => unreachable!("left_mut on non-inner"),
        }
    }
    fn right_mut(&mut self) -> &mut Option<Box<Node>> {
        match self {
            Node::Inner { right, .. } => right,
            _ => unreachable!("right_mut on non-inner"),
        }
    }
    fn left(&self) -> &Option<Box<Node>> {
        match self {
            Node::Inner { left, .. } => left,
            _ => unreachable!("left on non-inner"),
        }
    }
    fn right(&self) -> &Option<Box<Node>> {
        match self {
            Node::Inner { right, .. } => right,
            _ => unreachable!("right on non-inner"),
        }
    }
}

#[inline]
fn is_bit_set(keyhash: &[u8; 32], index: u8) -> bool {
    let pos = (index / 8) as usize;
    let bit = index % 8;
    (keyhash[pos] & (1 << (7 - bit))) > 0
}

/// Insert a leaf into an INNER node (Go inner.Insert), replicating the exact
/// branch/overwrite/new-inner behavior. `in.bit` is the bit this node tests.
fn inner_insert(node: &mut Node, key: &[u8], keyhash: &[u8; 32], value: &[u8]) {
    let (bit, l, r) = match node {
        Node::Inner { bit, left, right } => (*bit, left, right),
        _ => unreachable!("inner_insert on non-inner"),
    };
    if is_bit_set(keyhash, bit) {
        insert_child(r, bit, key, keyhash, value);
    } else {
        insert_child(l, bit, key, keyhash, value);
    }
}

fn insert_child(child: &mut Option<Box<Node>>, bit: u8, key: &[u8], keyhash: &[u8; 32], value: &[u8]) {
    match child {
        None => {
            // dead end: place the leaf
            *child = Some(Box::new(Node::Leaf { keyhash: *keyhash, key: key.to_vec(), value: value.to_vec() }));
        }
        Some(node) => {
            let is_leaf = matches!(node.as_ref(), Node::Leaf { .. });
            let overwrite = match node.as_ref() {
                Node::Leaf { keyhash: lkh, .. } => *lkh == *keyhash || bit == 255,
                _ => false,
            };
            if is_leaf && overwrite {
                if let Node::Leaf { value: lval, .. } = node.as_mut() {
                    lval.clear();
                    lval.extend_from_slice(value);
                }
                return;
            }
            if is_leaf {
                // split: new inner at bit+1, insert existing leaf first,
                // then the new leaf (Go: Insert(store, tmp, n))
                let (oldkh, oldk, oldv) = match node.as_ref() {
                    Node::Leaf { keyhash, key, value } => (*keyhash, key.clone(), value.clone()),
                    _ => unreachable!(),
                };
                let mut tmp = Box::new(Node::Inner { bit: bit + 1, left: None, right: None });
                inner_insert(&mut tmp, &oldk, &oldkh, &oldv);
                inner_insert(&mut tmp, key, keyhash, value);
                *node = tmp;
                return;
            }
            // inner node: recurse
            inner_insert(node, key, keyhash, value);
        }
    }
}

/// Recursively fetch a value by keyhash (Go inner.Get).
fn node_get(node: &Node, keyhash: &[u8; 32]) -> Option<Vec<u8>> {
    match node {
        Node::Leaf { keyhash: lkh, value, .. } => {
            if lkh == keyhash {
                Some(value.clone())
            } else {
                None
            }
        }
        Node::Inner { bit, left, right } => {
            if is_bit_set(keyhash, *bit) {
                match right {
                    Some(r) => node_get(r, keyhash),
                    None => None,
                }
            } else {
                match left {
                    Some(l) => node_get(l, keyhash),
                    None => None,
                }
            }
        }
    }
}

/// Fetch (key, value) by keyhash, descending at most `max_bit` bits.
/// Mirrors Go inner.GetKeyValue with valid_bit_count = max_bit: when the
/// trie depth reaches max_bit we return the leaf found there.
fn node_get_kv_prefix(node: &Node, keyhash: &[u8; 32], max_bit: u8) -> Option<(Vec<u8>, Vec<u8>)> {
    match node {
        Node::Leaf { key, value, .. } => Some((key.clone(), value.clone())),
        Node::Inner { bit, left, right } => {
            if *bit >= max_bit {
                // Go: used_bit_count > valid_bit_count → return current node
                // (a leaf here). Inner at depth == max_bit with both children
                // sharing the prefix is ambiguous; Go's dead-end logic returns
                // ErrNotFound. We return None for non-leaf.
                return None;
            }
            if is_bit_set(keyhash, *bit) {
                match right {
                    Some(r) => node_get_kv_prefix(r, keyhash, max_bit),
                    None => None,
                }
            } else {
                match left {
                    Some(l) => node_get_kv_prefix(l, keyhash, max_bit),
                    None => None,
                }
            }
        }
    }
}

/// Recursively fetch a value by keyhash (Go inner.Get).

/// Go inner.Delete: returns (empty, changed). Replicates the single-leaf
/// child collapse (isOnlyChildleaf).
fn node_delete(node: &mut Node, keyhash: &[u8; 32]) -> (bool, bool) {
    let (bit, l, r) = match node {
        Node::Inner { bit, left, right } => (*bit, left, right),
        _ => unreachable!("node_delete on non-inner"),
    };
    if is_bit_set(keyhash, bit) {
        match r {
            None => (false, false),
            Some(rnode) => {
                // recurse
                let (empty, changed) = if matches!(rnode.as_ref(), Node::Leaf { .. }) {
                    delete_leaf(rnode, keyhash)
                } else {
                    node_delete(rnode, keyhash)
                };
                if empty {
                    *r = None;
                }
                // collapse a single leaf child up
                if r.is_some() {
                    if let Some(n) = single_leaf_child_of(r) {
                        *r = n;
                    }
                }
                (l.is_none() && r.is_none(), changed)
            }
        }
    } else {
        match l {
            None => (false, false),
            Some(lnode) => {
                let (empty, changed) = if matches!(lnode.as_ref(), Node::Leaf { .. }) {
                    delete_leaf(lnode, keyhash)
                } else {
                    node_delete(lnode, keyhash)
                };
                if empty {
                    *l = None;
                }
                if l.is_some() {
                    if let Some(n) = single_leaf_child_of(l) {
                        *l = n;
                    }
                }
                (l.is_none() && r.is_none(), changed)
            }
        }
    }
}

fn delete_leaf(node: &mut Box<Node>, keyhash: &[u8; 32]) -> (bool, bool) {
    match node.as_mut() {
        Node::Leaf { keyhash: lkh, .. } => {
            if lkh == keyhash {
                (true, true)
            } else {
                (false, false)
            }
        }
        _ => (false, false),
    }
}

/// isOnlyChildleaf: an inner with exactly one child, which is a leaf.
fn single_leaf_child_of(node: &Option<Box<Node>>) -> Option<Option<Box<Node>>> {
    match node {
        None => None,
        Some(inner) => match inner.as_ref() {
            Node::Leaf { .. } => None,
            Node::Inner { left, right, .. } => {
                let has_l = left.is_some();
                let has_r = right.is_some();
                if has_l == has_r {
                    return None;
                }
                if has_l {
                    if matches!(left.as_ref().unwrap().as_ref(), Node::Leaf { .. }) {
                        Some(left.clone())
                    } else {
                        None
                    }
                } else {
                    if matches!(right.as_ref().unwrap().as_ref(), Node::Leaf { .. }) {
                        Some(right.clone())
                    } else {
                        None
                    }
                }
            }
        },
    }
}

/// The in-memory graviton tree (equivalent of a Tree over MemStore).
#[derive(Clone, Debug)]
pub struct Tree {
    root: Box<Node>, // always Inner{bit:0}
    pub treename: String,
}

/// Debug: enumerate all leaf keys in the tree (oracle/node diagnostics).
pub fn tree_keys(tree: &Tree) -> Vec<Vec<u8>> {
    fn walk(node: &Node, out: &mut Vec<Vec<u8>>) {
        match node {
            Node::Leaf { key, .. } => out.push(key.clone()),
            Node::Inner { left, right, .. } => {
                if let Some(l) = left {
                    walk(l, out);
                }
                if let Some(r) = right {
                    walk(r, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&tree.root, &mut out);
    out
}

impl Tree {
    pub fn new(treename: &str) -> Tree {
        Tree {
            root: Box::new(Node::Inner { bit: 0, left: None, right: None }),
            treename: treename.to_string(),
        }
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        if value.len() > MAX_VALUE_SIZE {
            panic!("value is longer then max allowed value size");
        }
        let kh = sum(key);
        inner_insert(&mut self.root, key, &kh, value);
    }

    /// Go GetKeyValueFromHash: look up by KEYHASH, return (key, value).
    /// Only the first `keyhash.len()*8` bits are walked (Go valid_bit_count =
    /// len*8) — so a 16-byte keyhash descends 128 bits and returns the leaf
    /// sharing that prefix, without checking the full hash.
    pub fn get_key_value_from_hash(&self, keyhash: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if keyhash.is_empty() || keyhash.len() > 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h[..keyhash.len()].copy_from_slice(&keyhash);
        node_get_kv_prefix(&self.root, &h, (keyhash.len() * 8) as u8)
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let kh = sum(key);
        node_get(&self.root, &kh)
    }

    pub fn delete(&mut self, key: &[u8]) {
        let kh = sum(key);
        let _ = node_delete(&mut self.root, &kh);
    }

    /// The merkle root hash of the whole tree (Go Tree.Hash()).
    pub fn hash(&self) -> [u8; 32] {
        self.root.hash()
    }

    /// Debug: dump all leaf (key, value) pairs (oracle diagnostics).
    pub fn debug_dump(&self) -> Vec<u8> {
        fn walk(node: &Node, out: &mut Vec<u8>) {
            match node {
                Node::Leaf { key, value, .. } => {
                    out.extend_from_slice(&(key.len() as u32).to_be_bytes());
                    out.extend_from_slice(key);
                    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
                    out.extend_from_slice(value);
                }
                Node::Inner { left, right, .. } => {
                    if let Some(l) = left {
                        walk(l, out);
                    }
                    if let Some(r) = right {
                        walk(r, out);
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out
    }
}

impl Default for Tree {
    fn default() -> Self {
        Tree::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_hash() {
        // Go: fresh GetTree("x").Hash() == 7706d6eab53679feae108fa5ee7260750a799d76f04faf7a2b3c2db778e70c04
        let t = Tree::new("x");
        assert_eq!(
            hex::encode(t.hash()),
            "7706d6eab53679feae108fa5ee7260750a799d76f04faf7a2b3c2db778e70c04"
        );
    }

    #[test]
    fn zeros_hash_matches_go() {
        // Go: zerosHash = f55be037b78cede07f9594d40f5b2d4e8bac852328c9b38433c84f457b1fe552
        assert_eq!(
            hex::encode(zeros_hash()),
            "f55be037b78cede07f9594d40f5b2d4e8bac852328c9b38433c84f457b1fe552"
        );
    }

    #[test]
    fn blake2s_baseline() {
        // blake2s-256("") — verified via Go's blake2s (golang.org/x/crypto)
        assert_eq!(
            grav_hash(b""),
            [
                0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35,
                0x4a, 0x7c, 0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd,
                0x1e, 0xd0, 0xee, 0xf9,
            ]
        );
    }

    #[test]
    fn put_get_roundtrip() {
        let mut t = Tree::new("t");
        t.put(b"a", b"1");
        t.put(b"b", b"2");
        assert_eq!(t.get(b"a"), Some(b"1".to_vec()));
        assert_eq!(t.get(b"b"), Some(b"2".to_vec()));
        assert_eq!(t.get(b"c"), None);
        t.delete(b"a");
        assert_eq!(t.get(b"a"), None);
        assert_eq!(t.get(b"b"), Some(b"2".to_vec()));
    }

    #[test]
    fn overwrite_same_key() {
        let mut t = Tree::new("t");
        t.put(b"k", b"v1");
        t.put(b"k", b"v2");
        assert_eq!(t.get(b"k"), Some(b"v2".to_vec()));
    }

    #[test]
    fn deterministic_hash() {
        let mut a = Tree::new("t");
        let mut b = Tree::new("t");
        for i in 0..50 {
            let k = format!("key{}", i);
            let v = format!("value{}", i);
            a.put(k.as_bytes(), v.as_bytes());
            b.put(k.as_bytes(), v.as_bytes());
        }
        assert_eq!(a.hash(), b.hash());
    }
}
