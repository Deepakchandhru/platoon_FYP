const snarkjs = require("snarkjs");
const path = require("path");

async function generateProof(input) {
    const wasmPath = path.join(__dirname, "../build/vehicleAuth_js/vehicleAuth.wasm");
    const zkeyPath = path.join(__dirname, "../build/circuit_final.zkey");

    const { proof, publicSignals } =
        await snarkjs.groth16.fullProve(
            input,
            wasmPath,
            zkeyPath
        );

    return { proof, publicSignals };
}

module.exports = { generateProof };
