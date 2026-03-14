pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template MerkleTreeVerifier(depth) {
    signal input leaf;
    signal input root;
    signal input pathElements[depth];
    signal input pathIndices[depth]; // must be 0 or 1

    // Enforce binary indices
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
    }

    signal hashes[depth + 1];
    hashes[0] <== leaf;

    // Declare all signals statically
    signal left[depth];
    signal right[depth];

    signal a1[depth];
    signal a2[depth];
    signal b1[depth];
    signal b2[depth];

    component hashers[depth];

    for (var i = 0; i < depth; i++) {
        hashers[i] = Poseidon(2);

        // Break arithmetic selection into quadratic steps
        a1[i] <== hashes[i] * (1 - pathIndices[i]);
        a2[i] <== pathElements[i] * pathIndices[i];
        left[i] <== a1[i] + a2[i];

        b1[i] <== pathElements[i] * (1 - pathIndices[i]);
        b2[i] <== hashes[i] * pathIndices[i];
        right[i] <== b1[i] + b2[i];

        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];

        hashes[i + 1] <== hashers[i].out;
    }

    root === hashes[depth];
}

template VehicleAuth(depth) {
    signal input vehicle_secret;
    signal input manufacturer_signature;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    signal input merkle_root;
    signal input capability_score;
    signal input trust_token;
    signal input capability_threshold;
    signal input trust_threshold;

    component commitHash = Poseidon(2);
    commitHash.inputs[0] <== vehicle_secret;
    commitHash.inputs[1] <== manufacturer_signature;

    signal commitment;
    commitment <== commitHash.out;

    component merkle = MerkleTreeVerifier(depth);
    merkle.leaf <== commitment;
    merkle.root <== merkle_root;

    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }

    component capCheck = GreaterEqThan(32);
    capCheck.in[0] <== capability_score;
    capCheck.in[1] <== capability_threshold;
    capCheck.out === 1;

    component trustCheck = GreaterEqThan(32);
    trustCheck.in[0] <== trust_token;
    trustCheck.in[1] <== trust_threshold;
    trustCheck.out === 1;
}

component main = VehicleAuth(1);
