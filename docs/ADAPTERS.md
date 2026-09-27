# Framework adapters

Your agent already runs inside a framework. These adapters hand it Arcaeon's
checks as ordinary tools, so the agent can log what it did and check a ledger
without you writing a line of glue.

Every adapter is built from one tool list, `arcaeon.adapters.tool_specs()`,
which reads the same OpenAPI document `arcaeon serve` answers. One tool per
free check route, named by its operationId (`log`, `verify`, `reconcile`,
`mandate_check` and the rest). The paid route (`/v1/seal`) is never a tool,
so an agent cannot spend by surprise.

Each tool sends its arguments to your local `arcaeon serve` and returns the
server's JSON as text. The verdict rides in the body with an integer `exit`:
0 good, 1 a bad finding, 2 bad usage, 3 COULD NOT LOOK. COULD NOT LOOK is not
a pass: a server that is down, or a ledger that is not there, comes back as
exit 3, never as an exception your framework might swallow and never as a
green answer.

No framework is a dependency of arcaeon. Each adapter imports its framework
inside `arcaeon_tools()`, so `import arcaeon.adapters.langchain` costs nothing
until you call it (tests/test_import_weight.py holds that line).

## Before any example

Start the server in the folder that holds your ledgers. The tools find it
through `~/.arcaeon/serve.json` and `~/.arcaeon/serve.token`, which it writes.

```console
$ arcaeon serve
```

Every example below ran, as written, in this repository's test suite
(tests/test_docs.py), against that server and a stand-in for each framework.
The output shown is what it printed.

## OpenAI Agents SDK

`pip install openai-agents`. Tools are `FunctionTool`s; pass them to
`Agent(name="checker", tools=arcaeon_tools())`.

```python
import asyncio, json
from arcaeon.adapters.openai_agents import arcaeon_tools

tools = {t.name: t for t in arcaeon_tools()}
for step in ("fetched", "summarized"):
    args = json.dumps({"ledger": "agents.jsonl", "fields": {"step": step}})
    asyncio.run(tools["log"].on_invoke_tool(None, args))
out = asyncio.run(tools["verify"].on_invoke_tool(None, '{"ledger": "agents.jsonl"}'))
r = json.loads(out)
print(r["verdict"], r["rows"], r["exit"])
```

```text
VERIFIED 2 0
```

## LangChain and LangGraph

`pip install langchain-core`. Tools are `StructuredTool`s whose `args_schema`
is the route's JSON schema; bind them to a model, or hand them as-is to a
LangGraph `ToolNode(arcaeon_tools())`.

```python
import json
from arcaeon.adapters.langchain import arcaeon_tools

tools = {t.name: t for t in arcaeon_tools()}
r = json.loads(tools["verify"].invoke({"ledger": "never-written.jsonl"}))
print(r["verdict"], r["exit"])
```

```text
COULD NOT LOOK 3
```

## LlamaIndex

`pip install llama-index-core`. Tools are `FunctionTool`s with an `fn_schema`
derived from the route's JSON schema; pass them to any LlamaIndex agent.

```python
import json
from arcaeon.adapters.llamaindex import arcaeon_tools

tools = {t.metadata.name: t for t in arcaeon_tools()}
tools["log"].call(ledger="llama.jsonl", fields={"step": "retrieved"})
r = json.loads(str(tools["verify"].call(ledger="llama.jsonl")))
print(r["verdict"], r["rows"], r["exit"])
```

```text
VERIFIED 1 0
```

## CrewAI

`pip install crewai`. Tools are `BaseTool`s with an `args_schema` derived from
the route's JSON schema; give them to `Agent(..., tools=arcaeon_tools())`.

```python
import json
from pathlib import Path
from arcaeon.adapters.crewai import arcaeon_tools

tools = {t.name: t for t in arcaeon_tools()}
for n in (1, 2):
    tools["log"].run(ledger="crew.jsonl", fields={"n": n})
p = Path("crew.jsonl")
p.write_bytes(p.read_bytes().replace(b'"n": 1', b'"n": 9'))
r = json.loads(tools["verify"].run(ledger="crew.jsonl"))
print(r["verdict"], r["exit"])
```

```text
BROKEN 1
```

## AutoGen

`pip install autogen-core` (AutoGen 0.4 and later). Tools are `BaseTool`s
with an args model derived from the route's JSON schema; give them to
`AssistantAgent(..., tools=arcaeon_tools())`.

```python
import asyncio, json
from autogen_core import CancellationToken
from arcaeon.adapters.autogen import arcaeon_tools

tools = {t.name: t for t in arcaeon_tools()}
token = CancellationToken()
asyncio.run(tools["log"].run_json({"ledger": "autogen.jsonl", "fields": {"step": 1}}, token))
r = json.loads(asyncio.run(tools["verify"].run_json({"ledger": "autogen.jsonl"}, token)))
print(r["verdict"], r["rows"], r["exit"])
```

```text
VERIFIED 1 0
```

## Any OpenAPI-capable framework

Semantic Kernel, the Vercel AI SDK, Dify, n8n and any other framework that
imports an OpenAPI document need no adapter at all. Point them at the
document: the committed copy is [docs/openapi.json](openapi.json), and a
running `arcaeon serve` answers the same one at `GET /openapi.json` (no token
needed for that route; every check route needs the token). The document is
built from the route table, so what the framework imports is what the server
answers.

`arcaeon connect generic-http` prints the server's URL, where the token
lives, and the OpenAPI URL, for pasting into such a framework. It writes
nothing.
