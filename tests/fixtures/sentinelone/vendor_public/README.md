# SentinelOne alerts: public samples

Source: https://github.com/Sentinel-One/purple-mcp/blob/e3060346cf8bbcaa60e1384ea7404fe058945604/tests/unit/libs/alerts/test_client.py
(`TestGetAlert.test_successful_get`, `alert_data`, lines 404-412;
`TestListAlerts.test_successful_list`, `response_data`, lines 451-473)
Commit: e3060346cf8bbcaa60e1384ea7404fe058945604
Retrieved: 2026-10-05
Licence: MIT (Sentinel-One/purple-mcp)
Trimming: none. These are Python dict literals in SentinelOne's own unit test,
converted to JSON with `ast.literal_eval` and `json.dumps` (indent 2; `False`
and `None` become `false` and `null`); no value changed. `purple_mcp_get_alert.json`
is the dict the mocked query returns, `{"alert": {...}}`, i.e. the GraphQL
`data` content without the `data` wrapper.
Redaction: none.

Caveat: these are vendor-written mocks in a public test, not a live tenant
export. SentinelOne's own API documentation sits behind a console login and was
not read.

| file | what it is |
|---|---|
| `purple_mcp_list_alerts.json` | `alerts.edges[].node` list response, one alert, `HIGH` / `NEW`, no analyst verdict |
| `purple_mcp_get_alert.json` | `alert` get response, `HIGH` / `NEW`, no analyst verdict |

Result: pass, no change. Both read COULD NOT LOOK (`no_verdict`), with the alert
id as `vendor_id` and `detectedAt` as `at`.
