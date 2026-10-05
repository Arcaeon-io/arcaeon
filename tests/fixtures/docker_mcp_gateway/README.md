# Docker MCP Gateway after-interceptor fixtures

Struct-derived, not a live capture and not a verbatim example. Docker's docs
have no full stdin sample. These bytes were built field by field from the Go
code that writes the interceptor's stdin. No gateway was run and nothing was
sent.

Source: github.com/docker/mcp-gateway at commit
a34df45d4ec0e941a9853ad768c4f6cd818966b3.

- `pkg/interceptors/interceptors.go` lines 90-145 (`ToMiddleware`). Only
  `tools/call` is intercepted (l.94). For `after`, the gateway calls
  `json.Marshal(response)` (l.122) and writes those bytes to the interceptor's
  stdin. `response` is the `mcp.Result` that the next handler returned, so it
  is a bare `*mcp.CallToolResult`. There is no JSON-RPC envelope, no request
  and no tool name. If stdout is non-empty, it is unmarshalled into
  `mcp.CallToolResult` (l.133-139) and replaces the response. If stdout is
  empty, the original response and error go back unchanged (l.142).
- Same file, lines 160-165 (`runExec`): `/bin/sh -c <argument>` with the
  message on stdin. `cmd.Output()` turns a non-zero exit into an error, so
  the call fails with "executing interceptor" (l.127-130) and stdout is
  dropped.
- `vendor/github.com/modelcontextprotocol/go-sdk/mcp/protocol.go` lines 76-120
  (go-sdk v1.4.1, per go.mod l.27). This is `CallToolResult`, in field order:
  `_meta,omitempty`, `content` (no omitempty, so a nil slice is `null`),
  `structuredContent,omitempty`, `isError,omitempty`. It has no `resultType`.
  `UnmarshalJSON` is at l.140-155.
- `vendor/.../mcp/content.go` lines 28-48: `TextContent` marshals as
  `type`, `text`, `_meta,omitempty`, `annotations,omitempty`. A content
  block's `_meta` therefore survives the round trip.
- `examples/interceptors/README.md` lines 34-36 and 82-87 confirm in prose
  that the "tool call response (`after`)" is passed as a JSON object on stdin,
  and give the example `after:exec:jq -c '.content[].text |= (.[:100])'`,
  which reads `.content` at the top level.

Files:

- `after_stdin_tool_result.json`: what `json.Marshal` gives for a
  `CallToolResult` holding one `TextContent` with `IsError` false and no Meta.
  Go writes compact JSON with no trailing newline. The tests seal the text
  and add `_meta` to the block, the same way a sealing server's go-sdk result
  would carry it.
- `after_stdin_error_null.json`: `null`. When the next handler returns an
  error, `response` is a nil interface and `json.Marshal` gives `null`
  (l.119-122). The interceptor prints nothing in that case, so the gateway
  returns its own error unchanged (l.142).
