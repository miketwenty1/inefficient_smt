use sha2::{Digest, Sha256};
use std::collections::HashMap;

type Hash = [u8; 32];

fn hash(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

fn get_bit(key: &[u8; 32], bit_index: usize) -> bool {
    let byte = key[bit_index / 8];
    let bit = 7 - (bit_index % 8);
    (byte >> bit) & 1 == 1
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Debug)]
struct InclusionProof {
    value: String,
    merkle_path: Vec<Hash>,
}

#[derive(Debug)]
struct SparseMerkleTree {
    nodes: HashMap<(usize, Hash), (Hash, Hash)>, // (depth, node_hash) -> (left_hash, right_hash)
    leaves: HashMap<Hash, Hash>,                 // key -> value hash
    root: Hash,
    default_hashes: Vec<Hash>,
}

impl SparseMerkleTree {
    fn new_from_values(values: Vec<String>) -> Self {
        let mut tree = SparseMerkleTree {
            nodes: HashMap::new(),
            leaves: HashMap::new(),
            root: [0u8; 32],
            default_hashes: vec![[0u8; 32]; 257],
        };

        tree.init_default_hashes();

        for value in values {
            let key = hash(value.as_bytes());
            let val_hash = key; // key == value
            tree.leaves.insert(key, val_hash);
        }

        tree.root = tree.build_tree();
        tree
    }

    fn init_default_hashes(&mut self) {
        for depth in (0..256).rev() {
            let left = self.default_hashes[depth + 1];
            let right = self.default_hashes[depth + 1];
            self.default_hashes[depth] = hash(&[left, right].concat());
        }
    }

    fn build_tree(&mut self) -> Hash {
        let mut current = self.leaves.clone();

        for depth in (0..256).rev() {
            let mut next = HashMap::new();
            let mut visited = std::collections::HashSet::new();

            for (&key, &val) in current.iter() {
                if visited.contains(&key) {
                    continue;
                }

                let bit = get_bit(&key, depth);
                let mut sibling_key = key;
                if bit {
                    sibling_key[depth / 8] &= !(1 << (7 - (depth % 8)));
                } else {
                    sibling_key[depth / 8] |= 1 << (7 - (depth % 8));
                }

                let left = if bit {
                    current
                        .get(&sibling_key)
                        .cloned()
                        .unwrap_or(self.default_hashes[depth + 1])
                } else {
                    val
                };

                let right = if bit {
                    val
                } else {
                    current
                        .get(&sibling_key)
                        .cloned()
                        .unwrap_or(self.default_hashes[depth + 1])
                };

                let parent_hash = hash(&[left, right].concat());
                next.insert(parent_hash, parent_hash);
                self.nodes.insert((depth, parent_hash), (left, right));
                visited.insert(key);
                visited.insert(sibling_key);
            }

            current = next;
        }

        current
            .keys()
            .next()
            .cloned()
            .unwrap_or(self.default_hashes[0])
    }

    fn get_inclusion_proof(&self, value: &str) -> Option<InclusionProof> {
        let key = hash(value.as_bytes());
        if !self.leaves.contains_key(&key) {
            return None;
        }

        let mut path = Vec::new();
        let mut current_hash = *self.leaves.get(&key).unwrap();

        for depth in (0..256).rev() {
            let bit = get_bit(&key, depth);

            let (left, right) = self.nodes.get(&(depth, current_hash)).cloned().unwrap_or((
                self.default_hashes[depth + 1],
                self.default_hashes[depth + 1],
            ));

            let sibling = if bit { left } else { right };
            path.push(sibling);

            current_hash = hash(&[left, right].concat());
        }

        Some(InclusionProof {
            value: value.to_string(),
            merkle_path: path,
        })
    }

    fn verify_inclusion(&self, value: &str) -> bool {
        let key = hash(value.as_bytes());
        self.leaves.contains_key(&key)
    }

    fn verify_non_inclusion(&self, value: &str) -> bool {
        let key = hash(value.as_bytes());
        !self.leaves.contains_key(&key)
    }

    fn root(&self) -> Hash {
        self.root
    }
}

fn main() {
    let values = vec![
        "value_str_1",
        "value_str_2",
        "value_str_3",
        "value_str_4",
        "value_str_5",
        "value_str_6",
        "value_str_7",
        "value_str_8",
        "value_str_9",
        "value_str_10",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    let tree = SparseMerkleTree::new_from_values(values);

    let check = "value_str_7";
    println!("Inclusion of '{}': {}", check, tree.verify_inclusion(check));
    println!(
        "Non-inclusion of 'value_str_11': {}",
        tree.verify_non_inclusion("value_str_11")
    );

    if let Some(proof) = tree.get_inclusion_proof(check) {
        println!("Inclusion proof for '{}':", check);
        for (i, h) in proof.merkle_path.iter().enumerate() {
            println!("  Level {}: {}", i, to_hex(h));
        }
    }
}
