const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

const vKey = JSON.parse(
    fs.readFileSync(
        path.join(__dirname, "../build/verification_key.json")
    )
);

async function verifyProof(proof, publicSignals) {
    return await snarkjs.groth16.verify(
        vKey,
        publicSignals,
        proof
    );
}

module.exports = { verifyProof };
