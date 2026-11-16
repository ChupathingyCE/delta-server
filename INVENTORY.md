# Inventory: the network node inside the Chupathingy site

The Chupathingy site (its private repository, "puma") runs two things in one
process: the Delta network node (the game list, device identity, the social
services) and the Chupathingy website (pages, statistics, bots, admin
panel). This file sorts its modules into the two, says what moved here, and
lists what a node reads from its settings, the services it talks to and
what was tied to chupathingy.org.

The site keeps running as it is. Nothing here changes it or what it serves.

## How the site is built

- `list_server.py` (about 10,900 lines) is the whole HTTP server: the
  interface, the game list (`GameList`), carnage reports and statistics
  (`Reports`), profiles, sessions and sign-in (`Profiles`), the admin panel
  (`Admin`), and the glue between the modules below. Every other module is
  called from it, and almost every test starts it.
- The modules beside it are mostly self-contained: each takes a SQLite
  connection, a lock and a clock, and is wired up in `main()`.
- One SQLite database (`reports.db`) holds everything: reports, profiles,
  sessions, devices, friends, clans, badges, servers, votes.

## Network node: moved here

| Module | What it is | How it moved |
| --- | --- | --- |
| `friends.py` | Friends, requests, blocks, social privacy, game invites | As is (SPDX header added) |
| `party.py` | Parties (memory only) | As is |
| `doorbell.py` | The doorbell: MQTT rings to game copies | As is |
| `clans.py` | Clans, ranks, invites, emblems | As is |
| `identity.py` | Device identity: enrollment, certificates, tokens, revocation, Quick Connect codes, the signer process | Default audience is `localhost`; the node passes its own |
| `delta_clients.py` | Other apps' client IDs and scopes | As is |
| `delta_list.py` | Delta List host fields, filters, listing fields | As is |
| `game_list_rules.py` | Which games a current release can join | As is |
| `delta_table.py` | Delta's signed legacy table puller | No default source; the URL and keys are settings |
| `blocked_names.py`, `blocked_names.txt` | Blocked names (slurs, hate) | As is |
| `addresses.py` | Address tags, never a whole address | As is |
| `ed25519.py` | Ed25519 in pure Python | As is (the RFC 8032 notice kept) |
| `mcc_maps.py` | MCC map names (needed by `delta_list.py`) | As is |
| `list_server.py`, part | The list (`GameList` cut down), the text and console list formats, the announce fields | Into `game_list.py` |
| `list_server.py`, part | The social answers (`social_state`, `social_join`, `social_invite`, the party and clan glue) | Into `social.py`, with the module globals set by the runner |
| `list_server.py`, part | The profile and link tables, presence, request limits | Into `accounts.py`, without passwords, sessions or email |
| `list_server.py`, part | The request handlers for the node's paths | Into `delta_node.py` |

Tests moved with them: the module-level test classes of `test_friends`,
`test_party`, `test_doorbell`, `test_clans`, `test_identity`,
`test_delta_clients`, `test_delta_list`, `test_game_list_rules`,
`test_blocked_names`, `test_addresses` and `test_delta_table`. The classes
that started the site's server were left out; `tests/test_node.py` covers
the same paths through the node instead.

## Network node: not moved yet

These belong to a node but are tied into the site more deeply, or wait on
a decision (see the README's Not done yet).

| Module or part | What it is | Why not yet |
| --- | --- | --- |
| `Profiles` sign-up, sign-in, sessions, Link Profile (`/v1/register`, `/v1/session/*`, `/v1/link`, `/v1/connect/*`) | Accounts with passwords, web sessions, the game's link codes | Whether a node keeps passwords at all is a decision; today an operator makes profiles from the command line |
| `account_email.py` | Account email: confirmation, resets | Goes with the decision above |
| `totp_seal.py` | Sealed authenticator secrets | Goes with accounts |
| `identity.py` Quick Connect approval from a web session (`claim_code`, `approve_code`), site sign-in (`/site-signin`) | Signing a device in from a signed-in page | Needs web sessions |
| `console_link.py` and the console paths (`/v1/console/link/*`, `/v1/console/claim`, `/v1/claim_challenge`, `/v1/claim_signed`) | Link Profile and claims for consoles without TLS | Tied to profiles and reports |
| `/v1/game/profile`, `/v1/game/players`, `/v1/game/privacy`, `/v1/game/unlink` | Delta Profile in the game | Their answers read statistics, badges and clans together |
| `GameList` probe, hosted games, relays | Checking a host can be reached; games listed from a profile | Needs the game's probe binary |
| `lobby.py`, `opence_masters.py` | OpenCE's public games from public MQTT brokers and their masters | Optional list sources; a decision whether a node carries them |
| `server_badges.py` | Signed server badges on listings | The badge keys are Chupathingy's; a node needs its own policy |
| `control.py`, `control_reports.py`, `ban_lists.py`, `control_client.py` | Delta Control: linked dedicated servers, roles, commands, reports, clips, shared bans | Large and tied to profiles; a later step |
| `analytics.py` (Delta Stats), `Reports` (carnage reports), `past_games.py`, `xbox_links.py` | Statistics | Separable in principle (they take the database and the address key), but they feed the site's pages; recent players in the social answers come from here |
| The region lookup (`GeoIP`) and activity counts | Regions on listings; players-online history | The region file is a separate download with its own license notice |

## The website: stays in the site

| Module | What it is |
| --- | --- |
| `web/`, `landing/`, `site_art.py`, `map_bitmaps.py`, `map_bounds.py`, `medal_assets.json` | Pages, art made from the game's maps, medals |
| `Admin` in `list_server.py`, `admin.py`, `quick_update.py` | The admin panel and its command line |
| `badges.py` | Profile badges |
| `donut.py`, `donut_watch.py`, `sarge.py`, `caboose.py` | Discord bots |
| `kofi.py` | Ko-fi thanks |
| `crashes.py`, `dumps.py` | Crash reports and the log upload page |
| `downloads.py` | The Downloads page |
| `playlist_votes.py`, `playlist_maps.py`, `playlists/`, `map_packs.json` | Chupathingy's own servers' playlists and votes |
| `dedicated_history.py` | Chupathingy's own servers' history |
| `cleanup.py`, `backfill_reports.py`, `fix_*.py`, `merge_duplicate_reports.py`, `purge_stats.py`, `redact_addresses.py` | One-off database tools |
| `docs/`, `tools/` | The site's own notes and tools |

## Dependencies between them

- Everything social reads profiles: `friends.py` and `clans.py` join on the
  `profiles` table (`player_id`, `handle`, `display`, `locked`). The node
  keeps that table with the site's columns, so the modules run unchanged.
- `identity.py` calls back into the site for who owns a copy, the copies
  of an account, and linking (`account_of`, `copies_of`, `link_copy`,
  `unlink_copy`); on revoke it ends the site's web sessions
  (`identity_sessions`, `sessions`). The node passes `accounts.py`'s hooks.
- The social answers read the game list (a friend's game), presence
  (memory), blocks and privacy, and on the site also carnage reports
  ("recent" players) and Delta Stats privacy (a hidden service record hides
  presence). The node has neither: recent players are empty and nothing is
  hidden that way.
- `delta_list.py` imports `mcc_maps.py` (map names) and `blocked_names.py`.
- `game_list_rules.py` reads the legacy table that `delta_table.py` puts in
  the data folder.
- The site's badges, Delta Control and statistics read the game list and
  profiles; none of them are needed by the node's paths.

## Settings and secrets

What the site reads from flags, and where it is in the node:

| Site flag | Node setting | Secret? |
| --- | --- | --- |
| `--address`, `--port`, `--data` | `node.address`, `node.port`, `node.data` | No |
| `--games-per-address` | `list.games_per_address` | No |
| `--anchors` | `list.anchors_file` | No |
| `--console-host` | `list.console_hosts` | No |
| `--delta-table` (and the keys in `delta_table.py`) | `delta_table.source`, `delta_table.keys` | No (public keys) |
| `--identity-issuer-cert`, `--identity-roots`, `--identity-audience` | `identity.issuer_cert_file`, `identity.roots`, `identity.audiences` | No |
| `--identity-signer`, `--identity-issuer-key` | `identity.signer_socket`, `identity.issuer_key_file` | The key file is; kept outside the repository, 0600 |
| `--doorbell-key-file`, `--doorbell-broker`, `--doorbell-user` | `doorbell.key_file`, `doorbell.brokers`, `doorbell.user` | The key file is |
| `--doorbell-password-file` | `doorbell.password_file` or `DELTA_DOORBELL_PASSWORD` | Yes |
| `address.key` in the data folder | the same, made at first start | Yes; never in the repository |

Site-only flags (not in the node): the probe command, history, region file,
relays, OpenCE broker and master listeners, the statistics budget, crash and
dump webhooks, Ko-fi token and webhook, sign-in sites, the dump host, badge
keys, official hosts, playlist maps and playlists, the GitHub token for
Quick Update, the playlist apply token, the site URL and SMTP settings,
account bans, clips, and the authenticator key file.

## External services

The site talks to: MQTT brokers for the doorbell (its own, with a password),
public MQTT brokers and OpenCE's masters (OpenCE public games), GitHub (the
legacy table and the releases API), Steam's public Workshop calls (MCC map
titles and pictures), Discord webhooks and the Discord API (the bots), Ko-fi,
an SMTP relay (account mail), and a region database file.

The node talks to: the doorbell brokers when `[doorbell]` is set, the legacy
table's source when `[delta_table]` is set, and Steam's public Workshop
calls only if something asks `mcc_maps.Workshop` (nothing in the node does
yet). Nothing else.

## Data stores

- The site: one SQLite database for everything, plus the data folder's
  files (address key, legacy table, crash reports, dumps, clips, Workshop
  pictures). Live lists, presence, parties, codes and limits are memory
  only.
- The node: one SQLite database (`node.db`, or `:memory:`) with the tables
  of `accounts.py`, `friends.py`, `clans.py`, `identity.py` and
  `delta_clients.py`, all with the site's column names; the address key and
  the legacy table in the data folder. The list, presence, parties, codes
  and limits are memory only, as on the site.

## What was tied to chupathingy.org

- `identity.DEFAULT_AUDIENCES` named the site's two host names: now
  `localhost`, and the node always passes `identity.audiences` or
  `node.domain`.
- `delta_table.SOURCE` pointed at the game repository's table branch: now
  empty; `delta_table.source` and `delta_table.keys` are settings.
- The legacy table puller's User-Agent named the site: now `delta-server`.
- The console host, the anchors and the doorbell brokers were flags or
  constants naming Chupathingy hosts: settings, empty by default.
- Reserved handles (the site keeps Chupathingy names for itself):
  `node.reserved_names`.
- Docstrings still mention the Chupathingy game repository's docs and our
  brokers where they explain where a format comes from; they are
  descriptions, not settings.
