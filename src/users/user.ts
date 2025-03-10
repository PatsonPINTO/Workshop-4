import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import {
  createRandomSymmetricKey,
  exportSymKey,
  symEncrypt,
  rsaEncrypt,
} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  _user.get("/status", (req, res) => {
    res.send("live");
  });
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // Lorsqu'un utilisateur reçoit un message, on retire le préfixe de 10 chiffres (s'il existe)
  _user.post("/message", (req, res) => {
    let { message } = req.body;
    if (message && message.length >= 10 && /^\d{10}/.test(message)) {
      message = message.slice(10);
    }
    lastReceivedMessage = message;
    res.send("success");
  });

  _user.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId } = req.body as SendMessageBody;
      lastSentMessage = message;
      
      const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      interface NodeRegistry {
        nodes: { nodeId: number; pubKey: string }[];
      }
      const registryData = (await registryResponse.json()) as NodeRegistry;
      const nodes = registryData.nodes;
      if (nodes.length < 3) {
        throw new Error("Not enough nodes in the registry");
      }
      nodes.sort(() => Math.random() - 0.5);
      const circuit = nodes.slice(0, 3);
      // Stocke simplement les nodeId dans le circuit
      lastCircuit = circuit.map(n => n.nodeId);

      // La destination finale pour l'utilisateur est le port complet: BASE_USER_PORT + destinationUserId
      const finalDest = (BASE_USER_PORT + destinationUserId).toString().padStart(10, "0");
      // Payload initial : destination finale + message
      let payload = finalDest + message;

      // Construction des couches d'encryption : du dernier nœud vers le premier
      for (let i = circuit.length - 1; i >= 0; i--) {
        let nextHop: string;
        if (i === circuit.length - 1) {
          nextHop = finalDest;
        } else {
          // IMPORTANT : pour les couches intermédiaires, utiliser le port complet du prochain nœud.
          nextHop = (BASE_ONION_ROUTER_PORT + circuit[i + 1].nodeId).toString().padStart(10, "0");
        }
        const messageToEncrypt = nextHop + payload;
        const symKey = await createRandomSymmetricKey();
        const symKeyExported = await exportSymKey(symKey);
        const encryptedLayer = await symEncrypt(symKey, messageToEncrypt);
        const encryptedSymKey = await rsaEncrypt(symKeyExported, circuit[i].pubKey);
        payload = encryptedSymKey + encryptedLayer;
      }

      const entryNodePort = BASE_ONION_ROUTER_PORT + circuit[0].nodeId;
      await fetch(`http://localhost:${entryNodePort}/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: payload }),
      });
      res.json({ result: "Message sent" });
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: errorMessage });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}
