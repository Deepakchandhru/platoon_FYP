const express = require("express");
const bodyParser = require("body-parser");

const { poseidonHash } = require("./zkp/poseidon");
const { generateProof } = require("./zkp/prover");
const { verifyProof } = require("./zkp/verifier");

const app = express();
app.use(bodyParser.json());

app.post("/zkp/commitment", async (req, res) => {
    const { vehicle_secret, manufacturer_signature } = req.body;

    const commitment = await poseidonHash(
        vehicle_secret,
        manufacturer_signature
    );

    res.json({ commitment });
});

app.post("/zkp/verify-vehicle", async (req, res) => {
    try {
        const { proof, publicSignals } =
            await generateProof(req.body);

        const valid = await verifyProof(proof, publicSignals);

        res.json({
            status: valid ? "APPROVED" : "REJECTED"
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.post("/zkp/hash-pair", async (req, res) => {
    try {
        const { a, b } = req.body;
        const hash = await poseidonHash(a, b);
        res.json({ hash });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.listen(4000, () =>
    console.log("Node ZKP service running on port 4000")
);
