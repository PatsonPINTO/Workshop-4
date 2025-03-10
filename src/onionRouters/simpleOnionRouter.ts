import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import {
    generateRsaKeyPair,
    exportPubKey,
    exportPrvKey,
    rsaDecrypt,
    symDecrypt,
    rsaEncrypt,
    importSymKey,
    exportSymKey,
} from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
    const onionRouter = express();
    onionRouter.use(express.json());
    onionRouter.use(bodyParser.json());

    // Generate RSA key pair for encryption and decryption
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const pubKeyStr = await exportPubKey(publicKey);
    
    // Register the node with the central registry
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nodeId, pubKey: pubKeyStr }),
    });

    let lastReceivedEncryptedMessage: string | null = null;
    let lastReceivedDecryptedMessage: string | null = null;
    let lastMessageDestination: number | null = null;

    onionRouter.get("/status", (req, res) => {
        res.send("live");
    });

    // Retrieve last received encrypted message
    onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
        res.json({ result: lastReceivedEncryptedMessage });
    });

    // Retrieve last received decrypted message
    onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
        res.json({ result: lastReceivedDecryptedMessage });
    });

    // Retrieve last known message destination
    onionRouter.get("/getLastMessageDestination", (req, res) => {
        res.json({ result: lastMessageDestination });
    });

    // Retrieve private key (should be protected in real use cases)
    onionRouter.get("/getPrivateKey", async (req, res) => {
        const prvKeyStr = await exportPrvKey(privateKey);
        res.json({ result: prvKeyStr });
    });

    onionRouter.post("/message", async (req, res) => {
        const { message } = req.body;
        lastReceivedEncryptedMessage = message;

        // Splitting encrypted symmetric key from encrypted payload
        const delimiterIndex = message.indexOf(":");
        if (delimiterIndex === -1) {
            console.error("Invalid message format");
            res.status(400).send("Invalid message format");
            return;
        }
        const encryptedSymKey = message.slice(0, delimiterIndex);
        const symEncryptedPayload = message.slice(delimiterIndex + 1);

        // Decrypt symmetric key using RSA private key
        const decryptedKeyStr = await rsaDecrypt(encryptedSymKey, privateKey);
        const symmetricKey = await importSymKey(decryptedKeyStr);

        // Decrypt the encrypted layer with the symmetric key
        const decryptedLayer = await symDecrypt(decryptedKeyStr, symEncryptedPayload);
        lastReceivedDecryptedMessage = decryptedLayer;

        // Extract next destination node ID and the remaining encrypted payload
        const destinationStr = decryptedLayer.slice(0, 10);
        const innerPayload = decryptedLayer.slice(10);
        const nextDestination = parseInt(destinationStr, 10);
        lastMessageDestination = nextDestination;

        // Forward the inner encrypted message to the next node
        const url = `http://localhost:${nextDestination}/message`;
        await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: innerPayload }),
        });

        res.send("success");
    });

    // Start the onion router server
    const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
        console.log(
            `Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`
        );
    });

    return server;
}
