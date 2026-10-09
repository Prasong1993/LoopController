import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

const base = "http://worker.test";
let apiKey;

async function call(action, fields = {}, key = apiKey) {
  return SELF.fetch(base + "/_api/control", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(key ? { "X-Project-Control-Key": key } : {})
    },
    body: JSON.stringify({ action, ...fields })
  });
}

async function addEvidence(runId, stage) {
  const response = await call("evidence", {
    runId,
    source: "automated-test:" + stage,
    content: "Verified test evidence for " + stage
  });
  expect(response.status).toBe(201);
  return response.json();
}

describe("Project Control API", () => {
  beforeEach(async () => {
    await env.DB.exec(
      "DROP TABLE IF EXISTS audit_events; " +
      "DROP TABLE IF EXISTS evidence; " +
      "DROP TABLE IF EXISTS runs; " +
      "DROP TABLE IF EXISTS api_keys;"
    );
    apiKey = undefined;
    const health = await SELF.fetch(base + "/_api/health");
    expect(health.status).toBe(200);
    expect((await health.json()).service).toBe("Project Control API");
  });

  it("enforces auth, stage evidence, audit integrity, and immutable completion", async () => {
    const openapi = await SELF.fetch(base + "/openapi.json");
    expect(openapi.status).toBe(200);
    expect((await openapi.json()).openapi).toBe("3.1.0");

    expect((await call("list")).status).toBe(401);
    expect((await SELF.fetch(base + "/_api/admin/bootstrap", {
      method: "POST",
      headers: { "X-Bootstrap-Token": "wrong-token" }
    })).status).toBe(401);

    const bootstrap = await SELF.fetch(base + "/_api/admin/bootstrap", {
      method: "POST",
      headers: { "X-Bootstrap-Token": "test-only-bootstrap-token" }
    });
    expect(bootstrap.status).toBe(201);
    apiKey = (await bootstrap.json()).apiKey;
    expect(apiKey).toMatch(/^pc_live_/);

    const secondBootstrap = await SELF.fetch(base + "/_api/admin/bootstrap", {
      method: "POST",
      headers: { "X-Bootstrap-Token": "test-only-bootstrap-token" }
    });
    expect(secondBootstrap.status).toBe(409);

    expect((await call("create", {})).status).toBe(400);
    expect((await call("list", {}, "invalid-key")).status).toBe(401);

    const created = await call("create", {
      title: "Automated acceptance test",
      description: "Temporary local test record"
    });
    expect(created.status).toBe(201);
    const runId = (await created.json()).runId;
    expect(runId).toBeTruthy();

    expect((await call("advance", { runId })).status).toBe(409);

    const stages = ["CONCEPT", "DESIGN", "EXECUTE", "RESULT", "VERIFY"];
    for (let i = 0; i < stages.length - 1; i++) {
      await addEvidence(runId, stages[i]);
      const advance = await call("advance", { runId });
      expect(advance.status).toBe(200);
      expect((await advance.json()).currentStage).toBe(stages[i + 1]);
    }

    const blockedVerify = await call("verify", { runId });
    expect(blockedVerify.status).toBe(409);
    expect((await blockedVerify.json()).missingStages).toContain("VERIFY");

    await addEvidence(runId, "VERIFY");
    const verified = await call("verify", { runId });
    expect(verified.status).toBe(200);
    const verification = await verified.json();
    expect(verification.status).toBe("COMPLETE");
    expect(verification.integrity.ok).toBe(true);
    expect(verification.integrity.evidenceCount).toBe(5);

    const audit = await call("audit", { runId });
    expect(audit.status).toBe(200);
    const auditBody = await audit.json();
    expect(auditBody.integrity.ok).toBe(true);
    expect(auditBody.integrity.eventCount).toBe(11);

    const detail = await call("detail", { runId });
    expect(detail.status).toBe(200);
    expect((await detail.json()).integrity.ok).toBe(true);

    expect((await call("evidence", {
      runId, source: "late", content: "must be rejected"
    })).status).toBe(409);
    expect((await call("advance", { runId })).status).toBe(409);
  });

  it("rejects malformed JSON, unknown actions, missing runs, and corrupted evidence", async () => {
    const bootstrap = await SELF.fetch(base + "/_api/admin/bootstrap", {
      method: "POST",
      headers: { "X-Bootstrap-Token": "test-only-bootstrap-token" }
    });
    expect(bootstrap.status).toBe(201);
    apiKey = (await bootstrap.json()).apiKey;

    const malformed = await SELF.fetch(base + "/_api/control", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Project-Control-Key": apiKey },
      body: "{not-json"
    });
    expect(malformed.status).toBe(400);
    expect((await call("not-a-real-action")).status).toBe(400);
    expect((await call("detail", { runId: "missing-run" })).status).toBe(404);
    expect((await call("advance")).status).toBe(400);

    const created = await call("create", { title: "Tamper test" });
    const runId = (await created.json()).runId;
    await addEvidence(runId, "CONCEPT");
    await env.DB.prepare("UPDATE evidence SET content = ? WHERE run_id = ?")
      .bind("tampered content", runId).run();

    const detail = await call("detail", { runId });
    expect(detail.status).toBe(200);
    expect((await detail.json()).integrity.ok).toBe(false);
    const advance = await call("advance", { runId });
    expect(advance.status).toBe(409);
  });

  it("detects audit event tampering before allowing a stage advance", async () => {
    const bootstrap = await SELF.fetch(base + "/_api/admin/bootstrap", {
      method: "POST",
      headers: { "X-Bootstrap-Token": "test-only-bootstrap-token" }
    });
    expect(bootstrap.status).toBe(201);
    apiKey = (await bootstrap.json()).apiKey;
    const created = await call("create", { title: "Audit tamper test" });
    const runId = (await created.json()).runId;
    await addEvidence(runId, "CONCEPT");
    await env.DB.prepare("UPDATE audit_events SET payload_json = ? WHERE run_id = ? AND seq = 1")
      .bind('{"stage":"ALTERED"}', runId).run();

    const audit = await call("audit", { runId });
    expect((await audit.json()).integrity.ok).toBe(false);
    const advance = await call("advance", { runId });
    expect(advance.status).toBe(409);
  });

});
