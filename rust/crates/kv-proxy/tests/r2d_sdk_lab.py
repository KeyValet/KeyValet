#!/usr/bin/env python3
"""Official Python SDKs against the Rust loopback gateway; no external API or real key."""
import argparse
import importlib.metadata
import json
from pathlib import Path
import subprocess
import httpx
import openai
import anthropic
import httpx2

p=argparse.ArgumentParser();p.add_argument("--fixture",required=True);p.add_argument("--output",required=True)
args=p.parse_args();out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
results=[];helper_log=out/"helper.jsonl";audit_log=out/"audit.jsonl"
def count():return len(helper_log.read_text().splitlines()) if helper_log.exists() else 0
with (out/"fixture.stderr").open("w") as stderr:
    process=subprocess.Popen([str(Path(args.fixture).resolve()),str(helper_log),str(audit_log)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,text=True)
    try:
        entry=json.loads(process.stdout.readline())
        versions={x:importlib.metadata.version(x) for x in ["openai","anthropic","httpx","httpx2","h2"]}
        for sdk in ["openai","anthropic"]:
            cls=openai.OpenAI if sdk=="openai" else anthropic.Anthropic
            default=cls(api_key="synthetic-only",base_url=entry["base"])
            results.append({"sdk":sdk,"version":versions[sdk],"default_read_timeout_s":default.timeout.read,"default_max_retries":default.max_retries})
            default.close()
            for h2_only in [False,True]:
                transport_module=httpx if sdk=="openai" else httpx2
                http_client=transport_module.Client(transport=transport_module.HTTPTransport(http1=not h2_only,http2=h2_only),timeout=600,trust_env=False)
                client=cls(api_key=entry["token"],base_url=entry["base"]+f"/api.{sdk}.com/v1",http_client=http_client)
                def call(state=None):
                    extra={"x-r2d-state":state} if state else {}
                    if sdk=="openai":return client.chat.completions.with_raw_response.create(model="synthetic",messages=[{"role":"user","content":"fixture"}],extra_headers=extra)
                    return client.messages.with_raw_response.create(model="synthetic",max_tokens=8,messages=[{"role":"user","content":"fixture"}],extra_headers=extra)
                begin=count();response=call();value=response.parse()
                text=value.choices[0].message.content if sdk=="openai" else value.content[0].text
                record={"sdk":sdk,"h2_only":h2_only,"case":"wildcard_subdomain","status":response.status_code,"http_version":response.http_response.http_version,"text":text,"helper_requests":count()-begin}
                assert text=="SDK_GATEWAY_OK" and record["helper_requests"]==1
                assert record["http_version"]==("HTTP/2" if h2_only else "HTTP/1.1")
                results.append(record);print(json.dumps(record),flush=True)
                for state,status in [("approval_denied",403),("approval_cancelled",409),("approval_expired",410)]:
                    begin=count()
                    try:call(state);raise AssertionError("Terminal approval unexpectedly succeeded")
                    except (openai.APIStatusError,anthropic.APIStatusError) as error:
                        record={"sdk":sdk,"h2_only":h2_only,"case":state,"status":error.status_code,"error_type":error.response.json()["error"]["type"],"helper_requests":count()-begin,"sdk_exception":type(error).__name__}
                        assert record["status"]==status and record["error_type"]=="keyvalet_"+state and record["helper_requests"]==1
                        results.append(record);print(json.dumps(record),flush=True)
                # *.domain excludes both the apex and lookalike suffixes before helper use.
                for host in [sdk+".com","evil"+sdk+".com"]:
                    client.base_url=entry["base"]+f"/{host}/v1";begin=count()
                    try:call();raise AssertionError("Wildcard boundary unexpectedly allowed")
                    except (openai.APIStatusError,anthropic.APIStatusError) as error:
                        record={"sdk":sdk,"h2_only":h2_only,"case":"wildcard_boundary","host":host,"status":error.status_code,"helper_requests":count()-begin}
                        assert record["status"]==403 and record["helper_requests"]==0
                        results.append(record);print(json.dumps(record),flush=True)
                client.close()
        (out/"results.json").write_text(json.dumps({"versions":versions,"results":results,"all_passed":True},indent=2)+"\n")
    finally:
        if process.poll() is None:
            process.stdin.write("stop\n");process.stdin.flush()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
