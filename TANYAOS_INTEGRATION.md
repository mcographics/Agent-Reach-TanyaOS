# Agent Reach for TanyaOS

This is a fork of Panniantong/Agent-Reach. Upstream's installer, configuration,
channel diagnostics and MIT license remain intact. TanyaOS adds
`agent_reach.tanya`, a bounded public read adapter with structured JSON results.
The upstream project remains an external capability layer; it does not own
Tanya's identity, permanent memory, decision authority or model inference.

The adapter reads public web text, RSS/Atom, GitHub repositories/search, and
single YouTube video metadata and available captions. Calls return source URLs,
retrieval timestamps and `external_untrusted` provenance. Availability checks
are local dependency checks, not claims that a live website works.

The adapter does not install software, import browser cookies, read upstream
credential configuration, send messages, post comments, mutate repositories,
download media, or invoke arbitrary shell commands. HTTP requests go directly
to public sites with DNS validation, pinned addresses, TLS host verification,
redirect checks, standard ports and response limits. Sites can rate-limit or
block reads; captions may be absent. No paid provider or hosted language model
is needed. Upstream social/login/Exa channels are retained but are not enabled
in TanyaOS by this integration.

Install this fork, not the unrelated PyPI package with the same name:

```powershell
python -m pip install .
python -m agent_reach.tanya status
python -m agent_reach.tanya web --url https://example.com
python -m agent_reach.tanya github_repo --repository Panniantong/Agent-Reach
python -m agent_reach.tanya rss --url https://github.com/Panniantong/Agent-Reach/releases.atom
```

TanyaOS registers `internet.*` skills through its existing kernel-gated skill
executor. That executor owns session permissions, audit records and memory
events. Retrieved content is external evidence, not executable instructions.
The adapter uses no account credentials; private GitHub or social account
access requires a separate, explicitly configured capability.
