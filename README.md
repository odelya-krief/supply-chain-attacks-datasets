# dataset-generator

Minimal dataset generator for collecting GitHub Security Advisory (GHSA) data to support training a supply-chain attack recognition model.

This tool fetches **global security advisories** from the GitHub Advisory Database API, supports basic filtering (ecosystem/severity/type), and writes the results to JSON.

Reference docs: `https://docs.github.com/en/rest/security-advisories?apiVersion=2022-11-28`

## Quickstart

1) **Set a GitHub token** (recommended for higher rate limits):

```bash
export GITHUB_TOKEN="YOUR_TOKEN"
```

2) **Fetch advisories** (example: npm):

```bash
python main.py fetch-advisories --ecosystem npm --max-pages 1 --out advisories-npm.json
```

## Configuration (env vars)

You can copy `.env-sample` to `.env` and fill values, or export variables in your shell.

- **GITHUB_TOKEN**: GitHub token (recommended; otherwise you may hit lower rate limits)
- **github_token**: alias for `GITHUB_TOKEN`
- **GITHUB_API_BASE_URL**: default `https://api.github.com`
- **GITHUB_API_VERSION**: default `2022-11-28`
- **GITHUB_USER_AGENT**: default `dataset-generator/0.1`
- **GITHUB_TIMEOUT_S**: default `30`
- **GITHUB_API_SLEEP_S**: default `0.0` (sleep between pages, to be gentle on rate limits)

## CLI usage

### `fetch-advisories`

Fetch global GitHub security advisories and output JSON.

Examples:

```bash
# npm advisories → JSON file
python main.py fetch-advisories --ecosystem npm --max-pages 2 --out advisories-npm.json
```

```bash
# pip advisories → stdout
python main.py fetch-advisories --ecosystem pip --max-pages 1
```

Arguments:
- `--ecosystem`: e.g. `npm`, `pip`, `rubygems`
- `--severity`: e.g. `low`, `medium`, `high`, `critical`
- `--type`: advisory type query param (e.g. `reviewed`, `unreviewed`, `malware`)
- `--per-page`: page size (max 100)
- `--max-pages`: safety limit for pagination
- `--out`: output file (if omitted, prints JSON to stdout)

## Output

The output file is a JSON array of advisory objects returned by GitHub. (No schema normalization yet—this repo is intentionally minimal to bootstrap dataset collection.)


