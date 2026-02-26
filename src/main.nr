use dep::std;
use dep::poseidon::poseidon::bn254;

global N: u32 = 4; // amount of quads input for merkle root calculation
global K: u32 = 2;        // number of disclosed terms
global TREE_DEPTH: u32 = 2; // for N=4

fn merkle_root_4(leaves: [Field; 4]) -> Field {
    // let h01 = poseidon2(leaves[0], leaves[1]);
    let h01 = bn254::hash_2([leaves[0], leaves[1]]);
    // let h23 = poseidon2(leaves[2], leaves[3]);
    let h23 = bn254::hash_2([leaves[2], leaves[3]]);
    //poseidon(h01, h23)
    let root = bn254::hash_2([h01, h23]);
    
    println(root);
    
    root
}

fn hash_leaf(s: Field, p: Field, o_val: Field, o_suf: Field, g: Field) -> Field {
    bn254::hash_5([s, p, o_val, o_suf, g])
}

// Alternative vector 
/* fn hash_leaf(q: [Field; 5]) -> Field {
    bn254::hash_5(q)
} */

// --- Idea: Permutation assertion ---
/* fn assert_permutation(
    unsorted: [Field; N],
    sorted: [Field; N],
    alpha: Field
) {
    let mut prod_unsorted = 1;
    let mut prod_sorted = 1;

    for i in 0..N {
        prod_unsorted *= (alpha - unsorted[i]);
        prod_sorted   *= (alpha - sorted[i]);
    }

    assert(prod_unsorted == prod_sorted);
} */


// --- Idea: Leaf Membership Check ---
/* fn assert_leaf_in_vector(
    leaf: Field,
    leaves: [Field; N]
) {
    let mut accumulator = 0;

    for i in 0..N {
        let is_equal = (leaf == leaves[i]);
        accumulator += is_equal as Field;
    }

    assert(accumulator >= 1);
} */

fn check_membership(disclosed: Field, quads: [[Field;5];N]) {

    let mut found: Field = 0;

    for i in 0..N {
        let q = quads[i];

        found += (q[0] == disclosed) as Field;
        found += (q[1] == disclosed) as Field;
        found += (q[2] == disclosed) as Field;
        found += (q[3] == disclosed) as Field;
        found += (q[4] == disclosed) as Field;
    }

    assert(found != 0); // found at least once
}


fn main(
    root: Field, // now private

    // --- Doesnt work as Field input ---
    // pub_key_x: pub Field,
    // pub_key_y: pub Field,
    // signature: pub [Field; 2],

    pub_key_x: pub [u8; 32],
    pub_key_y: pub [u8; 32],
    signature: [u8; 64], // now private

    leaves: [Field; N], // quads (sorted lexicographically)

    disclosed_h_terms: pub [Field; K], // publicly disclosed

    // leaf_index_q1: u32, // points to the position order

    // leaf terms
    /* s_q1: Field,
    p_q1: Field,
    o_val_q1: Field,
    o_suf_q1: Field,
    g_q1: Field, */

    // alternative vector of hashed terms
    all_h_term_sorted_like_rdf_lex: [[Field;5];N], // pasted after sorting (i.e. matches the lexicographic leaf sort)

    // witness leaves
    // leaves_unsorted: [Field; N],
    // leaves_sorted: [Field; N],

) {

    // println(o_suf_q1);

    // Re-compute leaves (not sorted currently)
    let leaf_q1: Field = hash_leaf(all_h_term_sorted_like_rdf_lex[0][0], all_h_term_sorted_like_rdf_lex[0][1], all_h_term_sorted_like_rdf_lex[0][2], all_h_term_sorted_like_rdf_lex[0][3], all_h_term_sorted_like_rdf_lex[0][4],);
    let leaf_q2: Field = hash_leaf(all_h_term_sorted_like_rdf_lex[1][0], all_h_term_sorted_like_rdf_lex[1][1], all_h_term_sorted_like_rdf_lex[1][2], all_h_term_sorted_like_rdf_lex[1][3], all_h_term_sorted_like_rdf_lex[1][4],);
    let leaf_q3: Field = hash_leaf(all_h_term_sorted_like_rdf_lex[2][0], all_h_term_sorted_like_rdf_lex[2][1], all_h_term_sorted_like_rdf_lex[2][2], all_h_term_sorted_like_rdf_lex[2][3], all_h_term_sorted_like_rdf_lex[2][4],);
    let leaf_q4: Field = hash_leaf(all_h_term_sorted_like_rdf_lex[3][0], all_h_term_sorted_like_rdf_lex[3][1], all_h_term_sorted_like_rdf_lex[3][2], all_h_term_sorted_like_rdf_lex[3][3], all_h_term_sorted_like_rdf_lex[3][4],);

    let re_computed_leaves:[Field; 4] = [leaf_q1, leaf_q2, leaf_q3, leaf_q4];
    // let leaf_q1 = 0x014ae910eaedf49564588eca60433d138d3d0f141edd171a4a362fce609436a8;

    // Compute Merkle root from sorted leaves
    // let computed_root = merkle_root(leaves_sorted);

    // Re-build merkle tree from leaves
    let computed_root = merkle_root_4(re_computed_leaves); // these leaves are sorted

    assert(computed_root == root); // compares hex strings

    // Verify the ECDSA signature of the merkle root
    let root_bytes: [u8; 32] = root.to_be_bytes();

    println(root_bytes);

    // Hash the root bytes before passing it to signature verification
    // This happens internally in Rust, when ecdsa signature happens
    // IMPORTANT: We remove hashing of root bytes in Rust and Noir implementation to achieve a correct signature verification
    
    // let root_bytes_hash = sha256::digest(root_bytes);

    let valid_signature = std::ecdsa_secp256k1::verify_signature(
        pub_key_x,
        pub_key_y,
        signature,
        root_bytes
    );

    assert(valid_signature);

    // Debugging:
    // println(leaf_q1);
    // println(leaves[leaf_index_q1]);

    println("More debugging:-----");

    println("recomputed leaves:");
    println(leaf_q1);
    println(leaf_q2);
    println(leaf_q3);
    println(leaf_q4);
    

    println("all passed leaves (sorted): matches up ");
    for i in 0..N {
        println(leaves[i]);
    }

    // Assert one of the leaves was leaf_q1
    // Have to constrain index first
    // assert(leaf_index_q1 < N);
    // assert(leaf_q1 == leaves[leaf_index_q1]);
    // Assert leaf_q1 subject is identical to disclosed_s_q1
    // assert(s_q1 == disclosed_s_q1);

    // Check the K disclosed terms for being among the hashed terms at least once
    for i in 0..K {
        check_membership(disclosed_h_terms[i], all_h_term_sorted_like_rdf_lex);
    }

}
