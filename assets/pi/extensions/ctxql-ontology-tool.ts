import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { createConnection } from "node:net";
import { relative, resolve } from "node:path";

const MAX_LEGACY_RESPONSE_BYTES = 256 * 1024;
const MAX_GRAPH_REQUEST_BYTES = 32 * 1024;
const MAX_GRAPH_RESPONSE_BYTES = 64 * 1024;
const MAX_SKILL_BYTES = 64 * 1024;
const SKILLS = {
  "ctxql-ontology": "skills/ctxql-ontology/SKILL.md",
  "ctxql-query": "skills/ctxql-query/SKILL.md",
  "graph-workspace": "skills/graph-workspace/SKILL.md",
  "read-loan-agreement": "skills/read-loan-agreement/SKILL.md",
  "read-loan-agreement-v2": "skills/read-loan-agreement-v2/SKILL.md",
} as const;

type Capability = "capabilities" | "ontology" | "entities" | "graph_query" | "graph_playground" | "source";

function bridgeEnvelope(envelope: unknown, maxResponseBytes: number, signal?: AbortSignal): Promise<unknown> {
  const socket = process.env.CTXQL_ONTOLOGY_SOCKET;
  const token = process.env.CTXQL_ONTOLOGY_TOKEN;
  if (!socket || !token) throw new Error("CTXQL host bridge unavailable");
  return new Promise((resolvePromise, rejectPromise) => {
    const connection = createConnection(socket);
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (error?: Error, value?: unknown) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      connection.destroy();
      if (error) rejectPromise(error); else resolvePromise(value);
    };
    const onAbort = () => finish(new Error("CTXQL host call aborted"));
    if (signal?.aborted) return onAbort();
    signal?.addEventListener("abort", onAbort, { once: true });
    connection.setTimeout(10_000);
    connection.on("connect", () => {
      connection.write(JSON.stringify({ token, ...(envelope as object) }) + "\n");
    });
    connection.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxResponseBytes) finish(new Error("CTXQL host response limit"));
      else chunks.push(chunk);
    });
    connection.on("timeout", () => finish(new Error("CTXQL host timeout")));
    connection.on("error", () => finish(new Error("CTXQL host bridge failure")));
    connection.on("end", () => {
      try {
        const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (result?.ok !== true || !("response" in result)) {
          finish(new Error(`CTXQL host denied: ${String(result?.error ?? "invalid_response")}`));
        } else finish(undefined, result.response);
      } catch {
        finish(new Error("CTXQL host invalid response"));
      }
    });
  });
}

async function hostCall(capability: Capability, callId: string, request: unknown, signal?: AbortSignal): Promise<unknown> {
  const encoded = Buffer.byteLength(JSON.stringify(request), "utf8");
  if ((capability === "graph_query" || capability === "graph_playground") && encoded > MAX_GRAPH_REQUEST_BYTES) {
    throw new Error("CTXQL graph request limit");
  }
  if (signal) {
    signal.addEventListener("abort", () => {
      void bridgeEnvelope({ kind: "cancel", call_id: callId }, MAX_GRAPH_RESPONSE_BYTES).catch(() => {});
    }, { once: true });
  }
  return bridgeEnvelope(
    { kind: "call", call_id: callId, capability, request },
    capability === "graph_query" || capability === "graph_playground"
      ? MAX_GRAPH_RESPONSE_BYTES
      : MAX_LEGACY_RESPONSE_BYTES,
    signal,
  );
}

const recordRefSchema = {
  oneOf: [
    { type: "object", additionalProperties: false, required: ["kind", "handle"], properties: { kind: { const: "handle" }, handle: { type: "string", minLength: 1, maxLength: 2048 } } },
    { type: "object", additionalProperties: false, required: ["kind", "id"], properties: { kind: { const: "temp" }, id: { type: "string", minLength: 1, maxLength: 2048 } } },
  ]
} as const;
const literalSchema = {
  type: "object", additionalProperties: false, required: ["lexical", "datatype", "language"],
  properties: {
    lexical: { type: "string", maxLength: 16384 },
    datatype: { type: "string", minLength: 1, maxLength: 2048 },
    language: { anyOf: [{ type: "string", minLength: 1, maxLength: 2048 }, { type: "null" }] },
  }
} as const;
const endpointSchema = {
  oneOf: [
    { type: "object", additionalProperties: false, required: ["kind", "record"], properties: { kind: { const: "record" }, record: recordRefSchema } },
    { type: "object", additionalProperties: false, required: ["kind", "value"], properties: { kind: { const: "literal" }, value: literalSchema } },
  ]
} as const;
const evidenceSchema = { type: "array", maxItems: 32, items: { type: "string", minLength: 1, maxLength: 2048 } } as const;
const editSchema = {
  oneOf: [
    { type: "object", additionalProperties: false, required: ["op", "temp_id", "local_id", "label", "evidence"], properties: { op: { const: "add_node" }, temp_id: { type: "string" }, local_id: { type: "string" }, label: { type: "string" }, evidence: evidenceSchema } },
    { type: "object", additionalProperties: false, required: ["op", "temp_id", "subject", "predicate", "object", "evidence", "fit_note"], properties: { op: { const: "add_claim" }, temp_id: { type: "string" }, subject: recordRefSchema, predicate: { type: "string" }, object: endpointSchema, evidence: evidenceSchema, fit_note: { type: "string", maxLength: 2048 } } },
    { type: "object", additionalProperties: false, required: ["op", "temp_id", "label", "scope", "definition_evidence", "referent_shape", "target_text", "members", "membership_evidence", "status"], properties: { op: { const: "add_reference" }, temp_id: { type: "string" }, label: { type: "string" }, scope: { type: "string" }, definition_evidence: evidenceSchema, referent_shape: { type: "string" }, target_text: { anyOf: [{ type: "string" }, { type: "null" }] }, members: { type: "array", maxItems: 100, items: recordRefSchema }, membership_evidence: evidenceSchema, status: { type: "string", enum: ["unresolved", "partial", "resolved"] } } },
    { type: "object", additionalProperties: false, required: ["op", "temp_id", "proposed", "existing", "comparison_evidence", "note"], properties: { op: { const: "add_hypothesis" }, temp_id: { type: "string" }, proposed: recordRefSchema, existing: recordRefSchema, comparison_evidence: evidenceSchema, note: { type: "string", maxLength: 2048 } } },
    { type: "object", additionalProperties: false, required: ["op", "temp_id", "code", "message", "relevant"], properties: { op: { const: "add_question" }, temp_id: { type: "string" }, code: { type: "string" }, message: { type: "string", maxLength: 2048 }, relevant: { type: "array", maxItems: 100, items: recordRefSchema } } },
    { type: "object", additionalProperties: false, required: ["op", "handle"], properties: { op: { const: "withdraw" }, handle: { type: "string", minLength: 1, maxLength: 2048 } } },
  ]
} as const;

function loadSkill(name: keyof typeof SKILLS): string {
  const root = realpathSync(process.cwd());
  const requested = resolve(root, SKILLS[name]);
  const resolved = realpathSync(requested);
  const withinRoot = relative(root, resolved);
  const metadata = lstatSync(requested);
  if (metadata.isSymbolicLink() || !metadata.isFile() || withinRoot.startsWith("..") || withinRoot === "" || metadata.size > MAX_SKILL_BYTES) {
    throw new Error("ctxql_skill denied");
  }
  const content = readFileSync(resolved, "utf8");
  if (Buffer.byteLength(content, "utf8") > MAX_SKILL_BYTES) throw new Error("ctxql_skill response limit");
  return content;
}

export default function ctxqlOntology(pi: ExtensionAPI) {
  const profile = process.env.CTXQL_PI_PROFILE;
  if (profile === "chat") {
    // Chat never performs an autonomous idle provider call. This lifecycle
    // hook is the installed Pi contract for stopping cache warming; there is
    // intentionally no invented RPC setting for it.
    pi.on("cache_warming_decision", async () => ({ action: "stop" }));
    pi.registerTool({
      name: "ctxql_capabilities",
      label: "CTXQL capabilities",
      description: "Inspect the host-selected read-only query profile, limits, explicit-label landing, source-read availability, and optional ontology status.",
      executionMode: "sequential",
      parameters: { type: "object", additionalProperties: false, properties: {} } as const,
      async execute(id, params, signal) {
        const response = await hostCall("capabilities", id, params, signal);
        return { content: [{ type: "text", text: JSON.stringify(response) }], details: response as object };
      }
    });
    pi.registerTool({
      name: "ctxql_ontology",
      label: "CTXQL ontology lookup",
      description: "Explore optional host-verified public vocabulary. Search concept wording and sensible synonyms; describe/hierarchy/vocabulary_status require an exact returned term IRI, not free text. Ontology concepts are not instance facts.",
      executionMode: "sequential",
      parameters: {
        type: "object", additionalProperties: false, required: ["operation", "query"],
        properties: { operation: { type: "string", enum: ["search", "describe", "hierarchy", "vocabulary_status"] }, query: { type: "string", minLength: 1, maxLength: 512 }, limit: { type: "integer", minimum: 1, maximum: 20 } }
      } as const,
      async execute(id, params, signal) {
        const response = await hostCall("ontology", id, params, signal);
        return { content: [{ type: "text", text: JSON.stringify(response) }], details: response as object };
      }
    });
    pi.registerTool({
      name: "ctxql_graph_query",
      label: "Authorized CTXQL graph query",
      description: "Run a bounded authorized CTXQL query, or an advertised ctxql.chat-inventory/v1 envelope for complete scoped counts and paginated entity lists. Serialize either in query. Load ctxql-query for syntax; inventory is not name search or identity merging.",
      executionMode: "sequential",
      parameters: { type: "object", additionalProperties: false, required: ["query"], properties: { query: { type: "string", minLength: 2, maxLength: MAX_GRAPH_REQUEST_BYTES } } } as const,
      async execute(id, params, signal) {
        const response = await hostCall("graph_query", id, params, signal);
        return { content: [{ type: "text", text: JSON.stringify(response) }], details: response as object };
      }
    });
    pi.registerTool({
      name: "ctxql_source",
      label: "Authorized CTXQL source evidence",
      description: "Read one bounded exact source-evidence span by a host-issued session reference. References and hashes do not grant access.",
      executionMode: "sequential",
      parameters: { type: "object", additionalProperties: false, required: ["reference"], properties: { reference: { type: "string", minLength: 1, maxLength: 2048 }, max_bytes: { type: "integer", minimum: 1, maximum: 16384 } } } as const,
      async execute(id, params, signal) {
        const response = await hostCall("source", id, params, signal);
        return { content: [{ type: "text", text: JSON.stringify(response) }], details: response as object };
      }
    });
    return;
  }
  if (profile !== "extraction") throw new Error("unknown CTXQL Pi profile");

  pi.registerTool({
    name: "ctxql_ontology",
    label: "CTXQL ontology lookup",
    description: "Explore host-pinned ontology terms within the host budget: search source wording and related financial concepts, then describe returned IRIs and inspect hierarchy where useful. Check definitions, format notes, property kind, domain/range and available restrictions; follow exposed class/property connections with focused lookups. A label or compatible datatype alone is not semantic fit. Missing constraints are not approval. Returned IRIs may be uncertified; do not invent terms or assume the initial briefing is exhaustive.",
    executionMode: "sequential",
    parameters: {
      type: "object", additionalProperties: false, required: ["operation", "query"],
      properties: {
        operation: { type: "string", enum: ["search", "describe", "hierarchy", "vocabulary_status"] },
        query: { type: "string", minLength: 1, maxLength: 512 },
        limit: { type: "integer", minimum: 1, maximum: 20 }
      }
    } as const,
    async execute(id, params, signal) {
      return { content: [{ type: "text", text: JSON.stringify(await hostCall("ontology", id, params, signal)) }], details: {} };
    }
  });

  pi.registerTool({
    name: "ctxql_entities",
    label: "CTXQL entity lookup",
    description: "Search or describe possible identities in the host-pinned, access-controlled entity snapshot",
    parameters: {
      type: "object", additionalProperties: false, required: ["operation", "query"],
      properties: {
        operation: { type: "string", enum: ["search", "describe"] },
        query: { type: "string", minLength: 1, maxLength: 512 },
        limit: { type: "integer", minimum: 1, maximum: 20 }
      }
    } as const,
    async execute(id, params, signal) {
      return { content: [{ type: "text", text: JSON.stringify(await hostCall("entities", id, params, signal)) }], details: {} };
    }
  });

  pi.registerTool({
    name: "ctxql_graph_query",
    label: "Authorized CTXQL graph query",
    description: "Run one bounded read-only inline CTXQL query. Load ctxql_skill ctxql-query for syntax and refinement guidance.",
    executionMode: "sequential",
    parameters: {
      type: "object", additionalProperties: false, required: ["query"],
      properties: {
        query: { type: "string", minLength: 2, maxLength: MAX_GRAPH_REQUEST_BYTES },
        max_nodes: { type: "integer", minimum: 1, maximum: 50 },
        max_claims: { type: "integer", minimum: 1, maximum: 100 },
        max_response_bytes: { type: "integer", minimum: 128, maximum: MAX_GRAPH_RESPONSE_BYTES },
        timeout_ms: { type: "integer", minimum: 1, maximum: 10_000 }
      }
    } as const,
    async execute(id, params, signal) {
      const response = await hostCall("graph_query", id, params, signal);
      return { content: [{ type: "text", text: JSON.stringify(response) }], details: response as object };
    }
  });

  pi.registerTool({
    name: "ctxql_graph_playground",
    label: "Private graph playground",
    description: "Import/release complete query graphs and edit or inspect private draft state. Imported facts are immutable context, not document evidence.",
    executionMode: "sequential",
    parameters: {
      type: "object", additionalProperties: false, required: ["operation"],
      properties: {
        operation: { type: "string", enum: ["import", "release_graph", "apply", "inspect", "view", "check"] },
        handle: { type: "string", minLength: 1, maxLength: 2048 },
        expected_revision: { type: "integer", minimum: 0 },
        idempotency_key: { type: "string", minLength: 1, maxLength: 2048 },
        edits: { type: "array", maxItems: 20, items: editSchema },
        view: { type: "string", enum: ["overview", "neighbourhood", "changes", "open_questions"] },
        max_bytes: { type: "integer", minimum: 128, maximum: MAX_GRAPH_RESPONSE_BYTES }
      }
    } as const,
    async execute(id, params, signal) {
      const response = await hostCall("graph_playground", id, params, signal);
      return { content: [{ type: "text", text: JSON.stringify(response) }], details: response as object };
    }
  });

  pi.registerTool({
    name: "ctxql_skill",
    label: "CTXQL extraction skill",
    description: "Load one allow-listed, hash-bound CTXQL extraction/query skill",
    parameters: {
      type: "object", additionalProperties: false, required: ["name"],
      properties: { name: { type: "string", enum: ["ctxql-ontology", "ctxql-query", "graph-workspace", "read-loan-agreement", "read-loan-agreement-v2"] } }
    } as const,
    async execute(_id, params) {
      const name = params.name as keyof typeof SKILLS;
      if (!(name in SKILLS)) throw new Error("ctxql_skill denied");
      return { content: [{ type: "text", text: loadSkill(name) }], details: { name } };
    }
  });
}
