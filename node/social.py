"""Delta's social answers: friends, presence, invites, parties and the
clan part of /v1/social/state, joined up from friends.py, party.py and
clans.py.

Copied from the Chupathingy site's list_server.py with as few changes as
could be: the module globals (PROFILES, GAMES, FRIENDS, PARTIES, CLANS)
are set by the runner (delta_node.py, configure). A node keeps no
carnage reports or Delta Stats, so "recent" players are always empty and
no profile hides its service record.

TODO(federation): friends, parties and presence between nodes (handles as
handle:domain) are delta-spec's federation.md; everything here is local
to this node.

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT
"""

import hashlib
import json
import re

import blocked_names
import delta_list
import friends
import party
from game_list import console_state, invite_locked, publicly_listed

SOCIAL_GAME_FIELDS = ("name", "map", "engine", "mode", "players", "maximum_players", "teams", "platform", "protocol",
                      "version", "build")
JOIN_LINK = re.compile(r"^(?:halo://join/)?([0-9a-fA-F]{44}|[0-9a-fA-F]{64})/?$")
GAME_CLAN_MEMBERS = 24  # a clan's members in the game's answer, at most (the rest counted)

PROFILES = None  # accounts.Accounts
GAMES = None  # game_list.GameList
FRIENDS = None  # friends.Friends
PARTIES = None  # party.Parties
CLANS = None  # clans.Clans


def configure(profiles, games, friends_, parties, clans_):
    global PROFILES, GAMES, FRIENDS, PARTIES, CLANS
    PROFILES, GAMES, FRIENDS, PARTIES, CLANS = profiles, games, friends_, parties, clans_


def stats_hidden(player_id: str) -> bool:
    """(the site's Delta Stats privacy; a node keeps no stats)"""
    return False


def recent_players(player_id: str) -> list:
    """(the site reads these from carnage reports; a node keeps none)"""
    return []


CLAN_GAME_FIELDS = ("map", "engine", "mode", "teams", "players", "maximum_players")


def clan_presence(handle: str, viewer: str, games: dict) -> dict:
    """a clan member's presence as viewer sees it, as a friend's is
    (friend_presence: offline to a viewer they block and while they appear
    offline, a game only while they show it; offline to a clanmate who isn't
    a friend while their "clan_presence" is "friends"): {"online", "playing", "game"
    (a listed game's CLAN_GAME_FIELDS, else null)}. Never its name or
    invite: joining stays the friends' (social_join)"""
    row = PROFILES.by_handle(handle) if FRIENDS is not None else None
    if not row:
        return {"online": False, "playing": False, "game": None}
    # (a member who shows their status to friends only: offline to a
    # clanmate who isn't one)
    if FRIENDS.privacy_of(row[0])["clan_presence"] == "friends" and not FRIENDS.are_friends(row[0], viewer):
        return {"online": False, "playing": False, "game": None}
    online, invite, game = friend_presence(row[0], viewer, games)
    return {"online": online, "playing": invite is not None,
            "game": {key: game[key] for key in CLAN_GAME_FIELDS if key in game} if game else None}


def game_clan(player_id: str, presence: bool = False) -> dict:
    """the clan part of the game's answers (/v1/game/profile, /v1/game/clan):
    {"clan": the profile's clan as its members see it, cut for the game
    ({"id", "name", "tag", "motto", "emblem", "created", "rank", "count",
    "hidden", "more", "members": [{"display", "rank", "you"?}]}) or None,
    "clan_invites": [{"id", "name", "tag", "count"}]}. With presence
    (/v1/game/clan, DELTA's CLAN): each member's "handle", "online",
    "playing" and "game" (clan_presence), and for a leader or officer
    "clan_invited" [{"handle", "time"}], the invites their clan has out"""
    if CLANS is None:
        return {"clan": None, "clan_invites": []}
    mine = CLANS.mine(player_id, GAME_CLAN_MEMBERS)
    clan = mine["clan"]
    answer = {}
    if clan:
        games = social_games() if presence else {}
        members = []
        for member in clan["members"]:
            # (handles only in DELTA's roster, where a leader picks whom to
            # kick: the profile's answer keeps to display names)
            line = {key: member[key] for key in (("handle",) if presence else ()) + ("display", "rank", "you") if key in member}
            if presence and not member.get("you"):
                line.update(clan_presence(member["handle"], player_id, games))
            members.append(line)
        clan = dict({key: clan[key] for key in ("id", "name", "tag", "motto", "emblem", "created", "rank", "count", "hidden", "more")},
                    members=members)
        if presence and clan["rank"] in ("leader", "officer"):
            answer["clan_invited"] = CLANS.invited(player_id)[:GAME_CLAN_MEMBERS]
    answer.update(clan=clan, clan_invites=[{key: i[key] for key in ("id", "name", "tag", "count")} for i in mine["invites"]])
    return answer


FRIEND_ACTIONS = ("", "request", "accept", "decline", "cancel", "remove", "block", "unblock", "privacy")
JOIN_REASONS = {
    "offline": "They're offline.",
    "not_playing": "They're not in a game.",
    "friends_only": "Only their friends can join their game.",
    "invite_only": "They only take players they invite.",
    "unlisted": "Their game isn't on the list. Ask them for an invite.",
    "locked": "Their game has a password. Ask them for the invite link.",
    "full": "Their game is full.",
    "closed": "Their game isn't taking players right now.",
    "not_available": "You can't join their game.",
}


def friends_action(player_id: str, body: dict, who) -> tuple:
    """a friends change from the site or the game (body["action"], one of
    FRIEND_ACTIONS; "" just reads): (200, {"result"?}) or (status,
    {"error"}). who is (handle, address) for the admin log"""
    action = body.get("action") or ""
    handle = str(body.get("handle", ""))[:24]
    if action not in FRIEND_ACTIONS:
        return 400, {"error": "Bad request."}
    try:
        if action == "request":
            return 200, {"result": FRIENDS.request(player_id, handle)}
        if action in ("accept", "decline"):
            FRIENDS.answer(player_id, handle, action == "accept")
        elif action == "cancel":
            FRIENDS.cancel(player_id, handle)
        elif action == "remove":
            FRIENDS.remove(player_id, handle)
        elif action == "block":
            FRIENDS.block(player_id, handle)
        elif action == "unblock":
            FRIENDS.unblock(player_id, handle)
        elif action == "privacy":
            appear = body.get("appear_offline")
            if appear is not None and not isinstance(appear, bool):
                return 400, {"error": "Bad request."}
            requests = body.get("requests")
            join = body.get("join")
            clan_presence = body.get("clan_presence")
            FRIENDS.set_privacy(player_id, None if requests is None else str(requests), None if join is None else str(join), appear,
                                None if clan_presence is None else str(clan_presence))
    except friends.Refused as refused:
        return refused.status, {"error": refused.message}
    return 200, {}


def social_games() -> dict:
    """the listed games by invite, for the friends' answers: as the public
    list has them (no blocked name, scrubbed), "locked" for a game with a
    password, its invite kept (it is handed out only by social_join)"""
    with GAMES.lock:
        locked_slots = set(GAMES.locked_slots)
    games = {}
    for game in GAMES.snapshot():
        if not publicly_listed(game):
            continue
        game = blocked_names.scrub(game)
        game["locked"] = invite_locked(game["invite"], locked_slots)
        games[game["invite"].lower()] = game
    return games


def social_game(game) -> dict:
    """what a friend's state or an invite shows of a listed game: its name,
    map, game type, counts and what it runs (SOCIAL_GAME_FIELDS); never its
    invite, address or roster"""
    return {key: game.get(key) for key in SOCIAL_GAME_FIELDS if key in game} if game else None


def playing_invite(player_id: str):
    """the invite of the game a profile's copy says it is in, if it shows
    it (Show when I'm playing, its service record shown); else None"""
    invite = PROFILES.presence_of(player_id)
    return None if invite is None or stats_hidden(player_id) else invite


def join_refusal(viewer: str, friend: str, invite: str, game, rule: str) -> str:
    """why viewer can't join friend's game (a JOIN_REASONS key), or "" if
    they can: the friend's "who can join" (an invite from them always
    lets you in), then the listed game's state. An unlisted game is
    joined by invite only"""
    invited = FRIENDS.invited(viewer, friend, invite)
    if not invited:
        if rule == "invite":
            return "invite_only"
        if rule == "friends" and not FRIENDS.are_friends(viewer, friend):
            return "friends_only"
    if game is None:
        return "" if invited else "unlisted"
    if game.get("locked"):
        return "locked"
    state = console_state(game)
    return "" if state == "open" else ("full" if state == "full" else "closed")


def friend_presence(friend: str, viewer: str, games: dict):
    """(online, invite, game) of a profile as viewer sees it: offline to a
    viewer it blocks, and to everyone while it appears offline"""
    if FRIENDS.blocks(friend, viewer):
        return False, None, None
    privacy = FRIENDS.privacy_of(friend)
    if privacy["appear_offline"]:
        return False, None, None
    invite = playing_invite(friend)
    online = invite is not None or FRIENDS.online(friend)
    return online, invite, (games.get(invite) if invite else None)



def social_state(player_id: str, mark: bool = False, limit: int = 0, clan: bool = False) -> dict:
    """a profile's friends state (GET /v1/social/state, the top of this
    file): "you", "friends" (online first; at most limit, "more" the rest,
    0 all), "requests", "invites", "blocked", "counts" and "cursor" (a
    digest of the rest: the same cursor, nothing changed). mark: a copy of
    the game asked, so the profile is online. clan: its clan too, as
    /v1/game/clan answers it ("clan", "clan_invites", "clan_invited"?:
    DELTA's CLAN, polled with the friends)"""
    if mark:
        FRIENDS.mark_online(player_id)
        if PARTIES is not None:
            PARTIES.touch(party_member(player_id, None, {}))
    games = social_games()
    profile = PROFILES.get(player_id) or {}
    privacy = FRIENDS.privacy_of(player_id)
    listed = []
    for friend, handle, display, since in FRIENDS.friend_rows(player_id):
        online, invite, game = friend_presence(friend, player_id, games)
        joinable = invite is not None and not join_refusal(player_id, friend, invite, game, FRIENDS.privacy_of(friend)["join"])
        listed.append({"handle": handle, "display": display, "since": since, "online": online, "playing": invite is not None,
                       "joinable": joinable, "game": social_game(game)})
    listed.sort(key=lambda f: (not f["online"], not f["playing"], f["handle"]))
    online_count = sum(1 for f in listed if f["online"])
    more = max(0, len(listed) - limit) if limit else 0
    if limit:
        listed = listed[:limit]
    invites = []
    for invite in FRIENDS.invites_for(player_id):
        sender = PROFILES.get(invite["from"])
        if not sender or sender.get("locked"):
            continue
        invites.append({"id": invite["id"], "from": sender["handle"], "display": sender["display"],
                        "time": int(invite["created"]), "expires": int(invite["created"] + friends.INVITE_LIFETIME),
                        "game": social_game(games.get(invite["invite"]))})
    requests = FRIENDS.requests_of(player_id)
    party_answer = party_answer_for(party_member(player_id, None, {}), player_id)
    answer = {"you": {"handle": profile.get("handle", ""), "display": profile.get("display", ""),
                      "online": not privacy["appear_offline"], "appear_offline": privacy["appear_offline"],
                      "show_presence": not PROFILES.presence_hidden(player_id),
                      "friend_requests": privacy["requests"], "who_can_join": privacy["join"],
                      "clan_presence": privacy["clan_presence"]},
              "friends": listed, "more": more, "requests": requests, "invites": invites,
              "blocked": FRIENDS.blocked_of(player_id), "recent": recent_players(player_id),
              "counts": {"friends": len(listed) + more, "online": online_count, "requests": len(requests["incoming"]),
                         "invites": len(invites), "party_invites": len(party_answer["party_invites"])}}
    answer.update(party_answer)
    if clan and CLANS is not None:
        answer.update(game_clan(player_id, presence=True))
    answer = blocked_names.scrub(answer)
    answer["cursor"] = hashlib.sha256(json.dumps(answer, sort_keys=True).encode()).hexdigest()[:16]
    return answer


def social_join(viewer: str, handle: str) -> tuple:
    """POST /v1/social/join: (200, {"join": "halo://join/...", "friend",
    "game"}) when the friend's game takes the viewer now, else (status,
    {"error", "reason"}). The invite is handed out here only"""
    found = PROFILES.by_handle(str(handle).strip().lower().lstrip("@")[:24])
    if not found or found[2] or found[0] == viewer:
        return 404, {"error": "No profile has that handle.", "reason": "unknown"}
    friend = found[0]
    online, invite, game = friend_presence(friend, viewer, social_games())
    reason = "offline" if not online else ("not_playing" if invite is None else "")
    if not reason:
        reason = join_refusal(viewer, friend, invite, game, FRIENDS.privacy_of(friend)["join"])
    # (to someone who isn't their friend and has no invite from them, every
    # refusal reads the same, so it can't tell whether they're online or
    # playing; a game open to anyone still lets them join)
    if reason and not FRIENDS.are_friends(viewer, friend) and not FRIENDS.invited(viewer, friend):
        reason = "not_available"
    if reason:
        return 409, {"error": JOIN_REASONS[reason], "reason": reason}
    return 200, {"join": "halo://join/" + invite, "friend": PROFILES.get(friend)["handle"], "game": social_game(game)}


def social_invite(sender: str, handle: str, invite: str = "") -> tuple:
    """POST /v1/social/invite: a friend invited to the sender's game (the
    invite given, else the one its presence says), re-checked: (200,
    {"ok", "id", "expires"}) or (status, {"error", "reason"?})"""
    invite = invite or PROFILES.presence_of(sender) or ""
    if not invite:
        return 409, {"error": "You're not in a game.", "reason": "not_playing"}
    game = social_games().get(invite)
    if game is not None:
        reason = "locked" if game.get("locked") else {"full": "full", "open": ""}.get(console_state(game), "closed")
        if reason:
            return 409, {"error": {"locked": "Your game has a password: share its invite link instead.",
                                   "full": "Your game is full.", "closed": "Your game isn't taking players right now."}[reason],
                         "reason": reason}
    try:
        invite_id = FRIENDS.invite(sender, str(handle)[:24], invite)
    except friends.Refused as refused:
        return refused.status, {"error": refused.message}
    return 200, {"ok": True, "id": invite_id, "expires": friends.INVITE_LIFETIME}


# ---------- parties (party.py): the game's /v1/party, and the party in
# /v1/social/state

PARTY_ACTIONS = ("", "create", "invite", "accept", "decline", "join", "leave", "kick", "lead", "rule", "code", "go")
PARTY_REASONS = {
    "locked": "Can't follow: the game has a password.",
    "full": "Can't follow: the game is full.",
    "closed": "Can't follow: the game isn't taking players.",
}


def party_member(player_id, game_id, body: dict, address: str = "") -> dict:
    """the member a copy is: its profile's, else its own (no profile), with
    the name and platform it sends (and its address, which party.py only
    counts by a hash of, never keeps)"""
    platform = str(body.get("platform", ""))
    return {"key": "p:" + player_id if player_id else "c:" + game_id, "player_id": player_id,
            "name": "" if player_id else party.clean_name(body.get("name")),
            "platform": platform if platform in delta_list.PLATFORMS else "", "address": address}


def party_go_view(invite: str, _party: dict) -> dict:
    """the leader's game as a member is told it: its link, or why they
    can't follow (the listed game's state; a game not listed is the
    leader's to share, so it is followed)"""
    game = social_games().get(invite)
    reason = ""
    if game is not None:
        reason = "locked" if game.get("locked") else {"full": "full", "open": ""}.get(console_state(game), "closed")
    answer = {"game": social_game(game)}
    if reason:
        answer.update(reason=reason, error=PARTY_REASONS[reason])
    else:
        answer["join"] = "halo://join/" + invite
    return answer


def party_answer_for(member: dict, player_id) -> dict:
    """{"party", "party_invites"} for a member (party_invites: a profile's
    alone): handles in place of profile IDs, names as the list shows them"""
    if PARTIES is None:
        return {"party": None, "party_invites": []}
    state = PARTIES.state_for(member, party_go_view)
    if state:
        for entry in state["members"]:
            owner = entry.pop("player_id")
            profile = PROFILES.get(owner) if owner else None
            entry["handle"] = profile["handle"] if profile else None
            # (no Delta profile: the game marks the name unverified)
            entry["verified"] = profile is not None
            if profile:
                entry["name"] = profile.get("display") or profile["handle"]
            elif blocked_names.blocked(entry["name"]):
                entry["name"] = "Player"
    invites = []
    for invite in PARTIES.invites_for(player_id) if player_id else []:
        sender = PROFILES.get(invite["from"])
        if not sender or sender.get("locked") or FRIENDS.blocks(player_id, invite["from"]):
            continue
        invites.append({"party": invite["party"], "from": sender["handle"], "display": sender["display"],
                        "size": invite["size"], "time": invite["time"], "expires": invite["expires"]})
    return blocked_names.scrub({"party": state, "party_invites": invites})


def party_action(member: dict, body: dict) -> tuple:
    """POST /v1/party's action (PARTY_ACTIONS; "" reads): (200, {"party",
    "party_invites"}) after it, or (status, {"error", "reason"})"""
    action = body.get("action") or ""
    if action not in PARTY_ACTIONS:
        return 400, {"error": "Bad request.", "reason": "bad"}
    try:
        if action == "create":
            PARTIES.create(member)
        elif action == "invite":
            found = PROFILES.by_handle(str(body.get("handle", "")).strip().lower().lstrip("@")[:24])
            if not found or found[2]:
                return 404, {"error": "No profile has that handle.", "reason": "unknown"}
            PARTIES.invite(member, found[0])
        elif action in ("accept", "decline"):
            party_id = str(body.get("party", ""))
            if not party.PARTY_ID.match(party_id):
                return 400, {"error": "Bad request.", "reason": "bad"}
            if action == "accept":
                PARTIES.accept(member, party_id)
            else:
                PARTIES.decline(member, party_id)
        elif action == "join":
            if not party.clean_code(body.get("code")):
                return 400, {"error": "That isn't a party code.", "reason": "bad"}
            PARTIES.join(member, body.get("code"))
        elif action == "leave":
            PARTIES.leave(member)
        elif action in ("kick", "lead"):
            member_id = str(body.get("member", ""))
            if not party.MEMBER_ID.match(member_id):
                return 400, {"error": "Bad request.", "reason": "bad"}
            (PARTIES.kick if action == "kick" else PARTIES.lead)(member, member_id)
        elif action == "rule":
            PARTIES.set_rule(member, str(body.get("join", "")))
        elif action == "code":
            PARTIES.new_code(member)
        elif action == "go":
            match = JOIN_LINK.match(str(body.get("invite", "")).strip())
            if not match:
                return 400, {"error": "bad invite", "reason": "bad"}
            PARTIES.go(member, match.group(1).lower())
        # (still here, and the name and platform it sends kept up)
        PARTIES.touch(member)
    except party.Refused as refused:
        return refused.status, {"error": refused.message, "reason": refused.reason}
    return 200, party_answer_for(member, member["player_id"])
