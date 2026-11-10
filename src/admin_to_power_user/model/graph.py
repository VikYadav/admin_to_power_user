"""Principal graph: who is (transitively) in which group, and which entitlements that gives."""

from __future__ import annotations

from collections import deque
from typing import Iterable

from admin_to_power_user.models import USERS_GROUP, Principal


class PrincipalGraph:
    def __init__(self, principals: dict[str, Principal], memberships: dict[str, set[str]]):
        self.principals = principals
        self.parents = memberships  # member key -> direct parent group keys

    def groups_of(
        self,
        key: str,
        exclude: Iterable[str] = (),
        extra: Iterable[str] = (),
    ) -> set[str]:
        """All groups `key` belongs to, transitively.

        `exclude` groups are dropped and not traversed (simulates removal from `admins`).
        `extra` groups are added as direct parents (simulates joining `power_users`).
        Everyone is implicitly in `users`.
        """
        excluded = set(exclude)
        seen: set[str] = set()
        queue = deque(self.parents.get(key, set()) | set(extra))
        while queue:
            g = queue.popleft()
            if g in seen or g in excluded:
                continue
            seen.add(g)
            queue.extend(self.parents.get(g, set()))
        seen.add(USERS_GROUP)
        return seen

    def members_of(self, group: str) -> set[str]:
        """Non-group principals that are transitively members of `group`."""
        children: dict[str, set[str]] = {}
        for member, parents in self.parents.items():
            for p in parents:
                children.setdefault(p, set()).add(member)
        out: set[str] = set()
        seen: set[str] = set()
        queue = deque([group])
        while queue:
            g = queue.popleft()
            if g in seen:
                continue
            seen.add(g)
            for m in children.get(g, set()):
                if m.startswith("group:"):
                    queue.append(m)
                else:
                    out.add(m)
        return out

    def entitlements(self, key: str, groups: set[str]) -> set[str]:
        ents: set[str] = set()
        for k in {key} | groups:
            p = self.principals.get(k)
            if p:
                ents |= p.entitlements
        return ents
