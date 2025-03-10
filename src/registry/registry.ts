import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // Route /status
  _registry.get("/status", (req: Request, res: Response) => {
    return res.send("live");
  });

  // Tableau pour stocker temporairement les nœuds enregistrés
  const nodes: Node[] = [];

  // Route POST pour enregistrer un nœud
  _registry.post("/registerNode", (req: Request, res: Response) => {
    const { nodeId, pubKey } = req.body as RegisterNodeBody;
    if (nodeId === undefined || !pubKey) {
      return res.status(400).json({ error: "Missing nodeId or pubKey" });
    }
    const index = nodes.findIndex((node) => node.nodeId === nodeId);
    if (index !== -1) {
      nodes[index].pubKey = pubKey;
    } else {
      nodes.push({ nodeId, pubKey });
    }
    return res.json({ result: "Node registered successfully" });
  });

  // Route GET pour récupérer le registre des nœuds
  _registry.get("/getNodeRegistry", (req: Request, res: Response) => {
    return res.json({ nodes });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
