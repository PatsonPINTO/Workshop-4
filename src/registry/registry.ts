import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

// Define the structure of a registered node
export type Node = { nodeId: number; pubKey: string };

// Expected request body format for registering a node
export type RegisterNodeBody = {
    nodeId: number;
    pubKey: string;
};

// Expected response format for retrieving all registered nodes
export type GetNodeRegistryBody = {
    nodes: Node[];
};

export async function launchRegistry() {
    const _registry = express();
    _registry.use(express.json());
    _registry.use(bodyParser.json());

    // Endpoint to check if the registry service is live
    _registry.get("/status", (req, res) => {
        res.send("live");
    });

    const nodes: Node[] = [];

    // Endpoint to register a new onion router node
    _registry.post("/registerNode", (req: Request, res: Response) => {
        const { nodeId, pubKey } = req.body as RegisterNodeBody;
        if (!nodes.some(n => n.nodeId === nodeId)) {
            nodes.push({ nodeId, pubKey });
        }
        res.send("success");
    });

    // Endpoint to retrieve the list of registered nodes
    _registry.get("/getNodeRegistry", (req, res) => {
        res.json({ nodes });
    });

    // Start the registry server
    const server = _registry.listen(REGISTRY_PORT, () => {
        console.log(`Registry is listening on port ${REGISTRY_PORT}`);
    });

    return server;
}
