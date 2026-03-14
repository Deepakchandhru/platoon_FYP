const circomlib = require("circomlibjs");

let poseidon;

async function initPoseidon() {
    if (!poseidon) {
        poseidon = await circomlib.buildPoseidon();
    }
}

async function poseidonHash(a, b) {
    await initPoseidon();
    return poseidon.F.toString(
        poseidon([BigInt(a), BigInt(b)])
    );
}

module.exports = { poseidonHash };
