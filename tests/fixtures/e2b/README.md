# E2B run receipt fixtures

Shape from public source, not a live capture.

These files were written by hand from E2B's public SDK source. No sandbox was
created, no E2B account or key was used, no code was run and nothing was sent
anywhere. Every id, name, path and output string is synthetic.

Sources read (2026-10-05):

- `CommandResult` (`stdout`, `stderr`, `exit_code`, `error`):
  shape from public source
  https://raw.githubusercontent.com/e2b-dev/E2B/main/packages/python-sdk/e2b/sandbox/commands/command_handle.py
- `Execution` (`results`, `logs`, `error`, `execution_count`), `Logs`
  (`stdout`, `stderr` as lists of strings), `ExecutionError` (`name`, `value`,
  `traceback`) and `Execution.to_json()`: shape from public source
  https://raw.githubusercontent.com/e2b-dev/E2B/main/packages/code-interpreter-python/e2b_code_interpreter/models.py
- `SandboxInfo` (`sandbox_id`, `template_id`, `metadata`, ...): shape from
  public source
  https://raw.githubusercontent.com/e2b-dev/E2B/main/packages/python-sdk/e2b/sandbox/sandbox_api.py
- `sandbox.commands.run(...)` usage: https://docs.e2b.dev/commands.md

The run objects carry no sandbox id; `sandbox_id`, `template_id` and
`metadata` are added at the top level by the caller that serialises the run.

- `command_ok.json`: a `CommandResult` with `exit_code` 0 and `error` null,
  plus the caller's sandbox id, template id and metadata.
- `command_failed.json`: a `CommandResult` with `exit_code` 2 and an error
  message.
- `execution_ok.json`: an `Execution` written field by field (logs and error
  as JSON values), `error` null, `execution_count` 1.
- `execution_to_json_error.json`: the shape `Execution.to_json()` prints:
  `logs` and `error` are themselves JSON-encoded strings, and
  `execution_count` is left out. The error is a synthetic ZeroDivisionError.
- `command_no_exit_code.json`: a `CommandResult` with `error` null and no
  `exit_code` key (derived for the end-to-end checks test, not a documented
  output); it reads COULD NOT LOOK (`no_exit_code`).

What the sources do not settle: whether a future SDK changes `to_json()` to
stop double-encoding `logs` and `error`, and what a JavaScript SDK caller
serialises. The JavaScript `CommandResult` names its exit code `exitCode`
(https://raw.githubusercontent.com/e2b-dev/E2B/main/packages/js-sdk/src/sandbox/commands/commandHandle.ts);
this adapter reads the Python names only, so a camelCase row has no
`exit_code` and reads COULD NOT LOOK.
