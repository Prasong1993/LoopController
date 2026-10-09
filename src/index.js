export default {
 async fetch(request, env) {
  const cors = {"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type,X-Project-Control-Key,X-Bootstrap-Token"};
  const reply = (data,status=200) => new Response(JSON.stringify(data),{status,headers:{...cors,"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"}});
  if(request.method==="OPTIONS") return new Response(null,{status:204,headers:cors});
  const url=new URL(request.url), stages=["CONCEPT","DESIGN","EXECUTE","RESULT","VERIFY"];
  const sha=async value=>{const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,"0")).join("");};
  const schema=[
   "CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY,key_hash TEXT NOT NULL UNIQUE,label TEXT NOT NULL,created_at TEXT NOT NULL,revoked_at TEXT)",
   "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY,title TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',current_stage TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,completed_at TEXT)",
   "CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY,run_id TEXT NOT NULL,stage TEXT NOT NULL,source TEXT NOT NULL,content TEXT NOT NULL,content_hash TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(run_id) REFERENCES runs(id))",
   "CREATE INDEX IF NOT EXISTS evidence_run_stage ON evidence(run_id,stage)",
   "CREATE TABLE IF NOT EXISTS audit_events (run_id TEXT NOT NULL,seq INTEGER NOT NULL,event_type TEXT NOT NULL,payload_json TEXT NOT NULL,prev_hash TEXT NOT NULL,event_hash TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(run_id,seq),FOREIGN KEY(run_id) REFERENCES runs(id))"
  ].join(";");
  const init=async()=>{await env.DB.exec(schema);};
  const hashEvent=async(runId,seq,eventType,payload,prevHash,createdAt)=>sha(JSON.stringify({runId,seq,eventType,payload,prevHash,createdAt}));
  const appendEvent=async(runId,eventType,payload)=>{
   const last=await env.DB.prepare("SELECT seq,event_hash FROM audit_events WHERE run_id=? ORDER BY seq DESC LIMIT 1").bind(runId).first();
   const seq=(last?.seq||0)+1, prevHash=last?.event_hash||"GENESIS", createdAt=new Date().toISOString();
   const eventHash=await hashEvent(runId,seq,eventType,payload,prevHash,createdAt);
   await env.DB.prepare("INSERT INTO audit_events(run_id,seq,event_type,payload_json,prev_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?)").bind(runId,seq,eventType,JSON.stringify(payload),prevHash,eventHash,createdAt).run();
   return {seq,eventType,payload,prevHash,eventHash,createdAt};
  };
  const integrity=async run=>{
   const er=await env.DB.prepare("SELECT seq,event_type,payload_json,prev_hash,event_hash,created_at FROM audit_events WHERE run_id=? ORDER BY seq").bind(run.id).all();
   const vr=await env.DB.prepare("SELECT id,stage,source,content,content_hash FROM evidence WHERE run_id=?").bind(run.id).all();
   const events=er.results||[], evidence=vr.results||[];
   if(!events.length||events[0].event_type!=="RUN_CREATED") return {ok:false,reason:"Missing RUN_CREATED event"};
   let prev="GENESIS",stage=null,completed=0; const logged=new Map();
   for(let i=0;i<events.length;i++){
    const e=events[i]; if(e.seq!==i+1||e.prev_hash!==prev) return {ok:false,reason:"Audit sequence or previous hash mismatch",seq:e.seq};
    let p; try{p=JSON.parse(e.payload_json);}catch{return {ok:false,reason:"Invalid audit payload JSON",seq:e.seq};}
    if(await hashEvent(run.id,e.seq,e.event_type,p,e.prev_hash,e.created_at)!==e.event_hash) return {ok:false,reason:"Audit event hash mismatch",seq:e.seq};
    prev=e.event_hash;
    if(i===0){if(p.stage!=="CONCEPT")return {ok:false,reason:"Run must begin at CONCEPT"};stage="CONCEPT";}
    else if(e.event_type==="STAGE_ADVANCED"){
     const idx=stages.indexOf(stage); if(p.fromStage!==stage||idx<0||p.toStage!==stages[idx+1])return {ok:false,reason:"Illegal stage transition",seq:e.seq}; stage=p.toStage;
    }else if(e.event_type==="EVIDENCE_ADDED"){
     if(p.stage!==stage||!p.evidenceId||!p.contentHash||logged.has(p.evidenceId))return {ok:false,reason:"Evidence audit event mismatch",seq:e.seq};
     logged.set(p.evidenceId,{stage:p.stage,source:p.source,contentHash:p.contentHash});
    }else if(e.event_type==="RUN_COMPLETED"){
     if(stage!=="VERIFY"||p.stage!=="VERIFY"||JSON.stringify(p.completedStages)!==JSON.stringify(stages))return {ok:false,reason:"Invalid completion event",seq:e.seq};completed++;
    }else return {ok:false,reason:"Unknown audit event type",seq:e.seq};
   }
   if(completed>1)return {ok:false,reason:"Duplicate completion events"};
   if(logged.size!==evidence.length)return {ok:false,reason:"Persisted evidence count differs from audit log"};
   for(const ev of evidence){const l=logged.get(ev.id);if(!l||l.stage!==ev.stage||l.source!==ev.source||l.contentHash!==ev.content_hash||await sha(ev.content)!==ev.content_hash)return {ok:false,reason:"Persisted evidence content or metadata does not match its recorded hash",evidenceId:ev.id};}
   if(run.current_stage!==stage)return {ok:false,reason:"Run stage differs from audit replay"};
   if(run.status==="COMPLETE"&&(completed!==1||stage!=="VERIFY"||!run.completed_at))return {ok:false,reason:"Completed run state does not match audit log"};
   if(run.status!=="COMPLETE"&&completed!==0)return {ok:false,reason:"Audit log marks run complete but run state does not"};
   return {ok:true,eventCount:events.length,evidenceCount:evidence.length,stage:stage,status:run.status,headHash:prev};
  };
  try{
   await init();
   if(url.pathname==="/_api/health"&&request.method==="GET")return reply({status:"ok",service:"Project Control API",version:"1.0.0-cloudflare",deterministicGates:true,storage:"D1"});
   if(url.pathname==="/openapi.json"&&request.method==="GET")return reply({openapi:"3.1.0",info:{title:"Project Control API",version:"1.0.0",description:"Evidence-gated project workflow controller"},servers:[{url:url.origin}],paths:{"/_api/health":{get:{summary:"Health check",responses:{"200":{description:"Healthy"}}}},"/_api/control":{post:{summary:"Run a control action",security:[{ProjectControlKey:[]}],responses:{"200":{description:"Success"},"400":{description:"Invalid request"},"401":{description:"Unauthorized"},"404":{description:"Not found"},"409":{description:"Workflow gate blocked"}}}},"/_api/admin/bootstrap":{post:{summary:"Create the first API key once",responses:{"201":{description:"Created"}}}}},components:{securitySchemes:{ProjectControlKey:{type:"apiKey",in:"header",name:"X-Project-Control-Key"}}}});
   if(url.pathname==="/_api/admin/bootstrap"&&request.method==="POST"){
    if(!env.BOOTSTRAP_TOKEN||(request.headers.get("X-Bootstrap-Token")||"")!==env.BOOTSTRAP_TOKEN)return reply({error:"Unauthorized"},401);
    const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM api_keys").first();if((count?.n||0)>0)return reply({error:"Bootstrap already completed"},409);
    const raw=new Uint8Array(32);crypto.getRandomValues(raw);
    const token="pc_live_"+btoa(String.fromCharCode(...raw)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
    const now=new Date().toISOString(),id=crypto.randomUUID();
    await env.DB.prepare("INSERT INTO api_keys(id,key_hash,label,created_at) VALUES(?,?,?,?)").bind(id,await sha(token),"Initial API key",now).run();
    return reply({status:"created",warning:"Save this key now; it is shown only once.",apiKey:token,createdAt:now},201);
   }
   if(url.pathname!=="/_api/control"||request.method!=="POST")return reply({error:"Not found"},404);
   const supplied=request.headers.get("X-Project-Control-Key")||"";if(!supplied)return reply({error:"Missing or invalid API key"},401);
   const key=await env.DB.prepare("SELECT id FROM api_keys WHERE key_hash=? AND revoked_at IS NULL").bind(await sha(supplied)).first();if(!key)return reply({error:"Missing or invalid API key"},401);
   let body;try{body=await request.json();}catch{return reply({error:"Request body must be valid JSON"},400);}
   const action=body?.action;if(!["list","create","detail","evidence","advance","verify","audit"].includes(action))return reply({error:"Invalid action"},400);
   if(action==="list"){const r=await env.DB.prepare("SELECT id,title,description,current_stage,status,created_at,updated_at,completed_at FROM runs ORDER BY created_at DESC").all();return reply({runs:r.results||[]});}
   if(action==="create"){
    if(typeof body.title!=="string"||!body.title.trim())return reply({error:"title is required"},400);
    if(body.title.length>200||(body.description!==undefined&&(typeof body.description!=="string"||body.description.length>4000)))return reply({error:"title or description is invalid or too long"},400);
    const id=crypto.randomUUID(),now=new Date().toISOString(),title=body.title.trim(),description=body.description||"";
    await env.DB.prepare("INSERT INTO runs(id,title,description,current_stage,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)").bind(id,title,description,"CONCEPT","ACTIVE",now,now).run();
    await appendEvent(id,"RUN_CREATED",{title:title,stage:"CONCEPT"});
    return reply({runId:id,title:title,description:description,currentStage:"CONCEPT",status:"ACTIVE",createdAt:now},201);
   }
   if(typeof body.runId!=="string"||!body.runId)return reply({error:"runId is required"},400);
   const run=await env.DB.prepare("SELECT * FROM runs WHERE id=?").bind(body.runId).first();if(!run)return reply({error:"Run not found"},404);
   if(action==="detail"){
    const ev=await env.DB.prepare("SELECT id,stage,source,content,content_hash AS contentHash,created_at AS createdAt FROM evidence WHERE run_id=? ORDER BY created_at,id").bind(run.id).all();
    return reply({runId:run.id,title:run.title,description:run.description,currentStage:run.current_stage,status:run.status,createdAt:run.created_at,updatedAt:run.updated_at,completedAt:run.completed_at,evidence:ev.results||[],integrity:await integrity(run)});
   }
   if(action==="audit"){
    const ev=await env.DB.prepare("SELECT seq,event_type AS eventType,payload_json AS payload,prev_hash AS prevHash,event_hash AS eventHash,created_at AS createdAt FROM audit_events WHERE run_id=? ORDER BY seq").bind(run.id).all();
    return reply({runId:run.id,integrity:await integrity(run),events:(ev.results||[]).map(e=>({...e,payload:JSON.parse(e.payload)}))});
   }
   if(run.status==="COMPLETE")return reply({error:"Completed runs are immutable"},409);
   if(action==="evidence"){
    if(typeof body.source!=="string"||!body.source.trim()||typeof body.content!=="string"||!body.content.trim())return reply({error:"source and content are required"},400);
    if(body.source.length>500||body.content.length>50000)return reply({error:"source or content is too long"},400);
    const id=crypto.randomUUID(),now=new Date().toISOString(),contentHash=await sha(body.content),source=body.source.trim();
    await env.DB.prepare("INSERT INTO evidence(id,run_id,stage,source,content,content_hash,created_at) VALUES(?,?,?,?,?,?,?)").bind(id,run.id,run.current_stage,source,body.content,contentHash,now).run();
    await appendEvent(run.id,"EVIDENCE_ADDED",{evidenceId:id,stage:run.current_stage,source:source,contentHash:contentHash});
    await env.DB.prepare("UPDATE runs SET updated_at=? WHERE id=?").bind(now,run.id).run();
    return reply({evidenceId:id,runId:run.id,stage:run.current_stage,source:source,contentHash:contentHash,createdAt:now},201);
   }
   if(action==="advance"){
    const check=await integrity(run);if(!check.ok)return reply({error:"Audit/evidence integrity check failed",integrity:check},409);
    const idx=stages.indexOf(run.current_stage);if(idx<0||idx>=stages.length-1)return reply({error:"Cannot advance beyond VERIFY; use verify"},409);
    const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM evidence WHERE run_id=? AND stage=?").bind(run.id,run.current_stage).first();
    if(!(count?.n>0))return reply({error:"Evidence is required for the current stage before advancing",currentStage:run.current_stage},409);
    const fromStage=run.current_stage,toStage=stages[idx+1],now=new Date().toISOString();
    await appendEvent(run.id,"STAGE_ADVANCED",{fromStage:fromStage,toStage:toStage});
    await env.DB.prepare("UPDATE runs SET current_stage=?,updated_at=? WHERE id=?").bind(toStage,now,run.id).run();
    return reply({runId:run.id,status:"ACTIVE",previousStage:fromStage,currentStage:toStage,updatedAt:now});
   }
   if(action==="verify"){
    if(run.current_stage!=="VERIFY")return reply({error:"Run must reach VERIFY before completion",currentStage:run.current_stage},409);
    const check=await integrity(run);if(!check.ok)return reply({error:"Audit/evidence integrity check failed",integrity:check},409);
    const missing=[];for(const s of stages){const c=await env.DB.prepare("SELECT COUNT(*) AS n FROM evidence WHERE run_id=? AND stage=?").bind(run.id,s).first();if(!(c?.n>0))missing.push(s);}
    if(missing.length)return reply({error:"Evidence is required for every stage",missingStages:missing},409);
    const now=new Date().toISOString();await appendEvent(run.id,"RUN_COMPLETED",{stage:"VERIFY",completedStages:stages});
    await env.DB.prepare("UPDATE runs SET status='COMPLETE',completed_at=?,updated_at=? WHERE id=?").bind(now,now,run.id).run();
    const updated=await env.DB.prepare("SELECT * FROM runs WHERE id=?").bind(run.id).first();
    return reply({runId:run.id,status:"COMPLETE",currentStage:"VERIFY",completedAt:now,integrity:await integrity(updated)});
   }
   return reply({error:"Unsupported action"},400);
  }catch(error){return reply({error:"Internal server error",detail:String(error?.message||error)},500);}
 }
};