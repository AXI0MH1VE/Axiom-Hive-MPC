use serde::{Deserialize, Serialize};

/// Merkle tree node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: String,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    pub fn new(hash: impl Into<String>) -> Self {
        Self {
            hash: hash.into(),
            left: None,
            right: None,
        }
    }

    pub fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }
}

/// Merkle proof for verifying inclusion in tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: String,
    pub path: Vec<(String, ProofDirection)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ProofDirection {
    Left,
    Right,
}

impl MerkleProof {
    pub fn new(leaf_hash: impl Into<String>) -> Self {
        Self {
            leaf_hash: leaf_hash.into(),
            path: Vec::new(),
        }
    }

    pub fn add_step(mut self, hash: impl Into<String>, direction: ProofDirection) -> Self {
        self.path.push((hash.into(), direction));
        self
    }

    /// Verify this proof against a root hash
    pub fn verify(&self, root_hash: &str) -> bool {
        let mut current = self.leaf_hash.clone();

        for (sibling, direction) in &self.path {
            current = match direction {
                ProofDirection::Left => hash_pair(&sibling, &current),
                ProofDirection::Right => hash_pair(&current, &sibling),
            };
        }

        current == root_hash
    }
}

/// Merkle tree implementation for AxiomHive
pub struct MerkleTree {
    root: Option<MerkleNode>,
    leaves: Vec<String>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            root: None,
            leaves: Vec::new(),
        }
    }

    pub fn add_leaf(&mut self, hash: impl Into<String>) {
        self.leaves.push(hash.into());
    }

    pub fn build(&mut self) {
        if self.leaves.is_empty() {
            self.root = None;
            return;
        }

        let mut nodes: Vec<MerkleNode> = self
            .leaves
            .iter()
            .map(|h| MerkleNode::new(h.clone()))
            .collect();

        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            for window in nodes.chunks(2) {
                let left_node = window[0].clone();
                let right_node = if window.len() > 1 {
                    window[1].clone()
                } else {
                    window[0].clone()
                };

                let parent_hash = hash_pair(&left_node.hash, &right_node.hash);
                let mut parent = MerkleNode::new(parent_hash);
                parent.left = Some(Box::new(left_node));
                parent.right = Some(Box::new(right_node));

                next_level.push(parent);
            }

            nodes = next_level;
        }

        self.root = nodes.pop();
    }

    pub fn root_hash(&self) -> Option<String> {
        self.root.as_ref().map(|n| n.hash.clone())
    }

    /// Generate a proof of inclusion for a leaf
    pub fn proof_for_leaf(&self, leaf_hash: &str) -> Option<MerkleProof> {
        if let Some(root) = &self.root {
            let mut proof = MerkleProof::new(leaf_hash);
            self.proof_recursive(root, leaf_hash, &mut proof)?;
            Some(proof)
        } else {
            None
        }
    }

    fn proof_recursive(
        &self,
        node: &MerkleNode,
        target: &str,
        proof: &mut MerkleProof,
    ) -> Option<bool> {
        if node.hash == target && node.is_leaf() {
            return Some(true);
        }

        if let Some(left) = &node.left {
            if let Some(found) = self.proof_recursive(left, target, proof) {
                if let Some(right) = &node.right {
                    proof.path.push((right.hash.clone(), ProofDirection::Right));
                }
                return Some(found);
            }
        }

        if let Some(right) = &node.right {
            if let Some(found) = self.proof_recursive(right, target, proof) {
                if let Some(left) = &node.left {
                    proof
                        .path
                        .insert(0, (left.hash.clone(), ProofDirection::Left));
                }
                return Some(found);
            }
        }

        None
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_pair(left: &str, right: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_leaf() {
        let mut tree = MerkleTree::new();
        tree.add_leaf("hash1");
        tree.build();

        assert_eq!(tree.root_hash(), Some("hash1".to_string()));
    }

    #[test]
    fn test_merkle_tree_multiple_leaves() {
        let mut tree = MerkleTree::new();
        tree.add_leaf("hash1");
        tree.add_leaf("hash2");
        tree.add_leaf("hash3");
        tree.add_leaf("hash4");
        tree.build();

        assert!(tree.root_hash().is_some());
    }

    #[test]
    fn test_merkle_proof_verification() {
        let mut tree = MerkleTree::new();
        tree.add_leaf("hash1");
        tree.add_leaf("hash2");
        tree.build();

        let root = tree.root_hash().unwrap();
        let proof = tree.proof_for_leaf("hash1").unwrap();

        assert!(proof.verify(&root));
    }

    #[test]
    fn test_hash_pair_deterministic() {
        let hash1 = hash_pair("a", "b");
        let hash2 = hash_pair("a", "b");
        assert_eq!(hash1, hash2);
    }
}
