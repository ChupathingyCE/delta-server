# delta-server

> **Draft for discussion.** This is the work Chupathingy already has, separated out so other projects can read it and shape a shared spec. Nothing here is final: open an issue for anything that should be in, out or different.

Run your own Delta network node: the game list, device identity and the
social services (friends, presence, invites, parties, clans) that Delta
clients use, in standard-library Python.

delta-server is the reference node for the Delta network spec. It is not the
dedicated game server (that is chupathingy-server) and not the Chupathingy
website: the site at stats.chupathingy.org runs its own code, which this was
taken from, and stays the live service.

## Status

Early, and private until a security review. It starts, serves the node's
paths on the loopback address, and its tests pass. Do not run it on the
internet yet.

## Run it locally

Python 3.11 or newer (3.9 and 3.10 work without a config file). No
packages to install.

```
cp config.example.toml config.toml        # optional; config.toml stays out of git
python3 node/delta_node.py --config config.toml serve
curl http://127.0.0.1:8390/v1/health
curl http://127.0.0.1:8390/v1/node
```

Make a profile for a copy of the game (until account sign-up is decided):

```
python3 node/delta_node.py --config config.toml profile-add church --player-key <64 hex digits>
python3 node/delta_node.py --config config.toml link <copy's player ID> church
```

Device identity needs an issuer certificate signed by root keys you trust;
without one, `/v1/identity/*` answers 503 and games keep using their player
keys. `python3 node/identity.py issuer-key --out FILE` makes an issuer key
(keep it outside the repository); signing its certificate is up to whoever
holds your root keys.

## Run your own network

A node is one network on the spec's federation ([federation.md](https://github.com/ChupathingyCE/delta-spec/blob/main/federation.md)):
its players' names are `handle:yourdomain`, and any game that trusts your
root keys checks them offline. Keep root keys off the server, on a machine
you trust, and never in a repository:

```
python3 node/federation.py root-keys --domain example.org --dir KEYS     # two root keys + roots.json
python3 node/identity.py issuer-key --out ISSUER.key                      # on the server
python3 node/federation.py issuer-cert --root-key KEYS/example.org-root-primary.key \
    --issuer-public <the issuer's public key> --out issuer.cert           # back on the root keys' machine
```

Then set `[federation] network` and `roots_file` (the roots.json) and
`[identity] issuer_cert_file` and `signer_socket` (or `issuer_key_file` for
local tests). The node serves `/.well-known/open-network/roots.json`; it
must also answer at `https://example.org/.well-known/open-network/roots.json`
(your reverse proxy), which is where lists of networks take your keys from.
Make a new issuer key and certificate every few months.

A list of networks is made from networks' roots.json files and signed by
whoever publishes it, with a key set of its own (never the signed table's);
a node can serve one at `/v1/delta/networks`. Games check only their own
network's revocation list for now, so another network's revoked device
stays verified until its certificate expires (7 days):

```
python3 node/federation.py list-keys --dir LISTKEYS                  # the list's own primary + recovery
python3 node/federation.py list-make --serial 1 --roots a/roots.json b/roots.json --out networks.json
python3 node/federation.py list-sign --key LISTKEYS/list-primary.key networks.json
python3 node/federation.py check --list networks.json --list-key <hex> --home example.org \
    --home-root <hex> --issuer <CISS hex> --device <CDEV hex>
```

Tests:

```
python3 -m unittest discover -s tests -t .
```

## What it serves

`node/delta_node.py` lists the paths at the top. In short: the game list
(`/v1/announce`, `/v1/withdraw`, `/v1/games`, `/v1/games.txt`, the console
list), device identity (`/v1/identity/*`), presence, friends, invites,
parties and clans (`/v1/presence`, `/v1/social/*`, `/v1/party`,
`/v1/game/friends`, `/v1/game/clan`), and `/v1/node` (what this node runs).
It never shows or stores a whole IP address.

## Settings and secrets

Every setting is in `config.example.toml`. Secrets never go in the file:
keys are files outside the repository, and the doorbell password can come
from `DELTA_DOORBELL_PASSWORD`. Any string setting can also be set as
`DELTA_<SECTION>__<NAME>`.

## Not done yet

- **Federation between networks' social parts**: friends, invites and
  parties across networks. Names, roots.json and the list of networks are
  in (above); the code marks the rest with `TODO(federation)`.
- **Accounts**: sign-up, passwords, email and web sign-in are the site's
  today. Whether a node keeps passwords, or only device keys, is open.
- **Production hardening**: TLS is a reverse proxy's job; the signer
  process, service user, rate limits under load, backups and logging need
  a review before anyone runs this publicly.
- **Migrations from the site**: the tables use the site's column names, but
  there is no tool to move a site database's profiles, links, friends,
  clans or devices into a node.
- **More of the site's node parts**: the probe, console Link Profile,
  Delta Control, server badges and statistics. INVENTORY.md lists them.

## License

MIT (LICENSE). `node/ed25519.py` also carries the RFC 8032
reference code's Simplified BSD notice (LICENSES/BSD-2-Clause.txt).
Authors are in AUTHORS.md.
