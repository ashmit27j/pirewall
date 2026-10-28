"""`FairShareHistory`: a bounded history one source cannot flush (KNOWN_ISSUES.md #21).

A plain `deque(maxlen=n)` evicts strictly oldest-first, so a flood from a
single source replaced every one of the 500 detection, threat and flow
records within seconds, taking with them the port-scan records from a
different source captured just before it (attack-lab benchmark,
2026-09-10).

This container keeps the same bound and evicts from whichever key holds the
most entries, oldest first within that key. Ties go to the key whose oldest
entry is oldest overall. The result:

* With one key, or with every key holding an equal share, it is exactly
  oldest-first, as before.
* A single-source flood evicts only its own older records once it is the
  largest holder, so every other source's records survive it.
* A flood that spoofs a fresh source per packet gives every key one entry,
  so it degrades to oldest-first. The bound still holds. This case is
  covered only by the Wazuh copy (KNOWN_ISSUES.md #6), not by this.

Memory stays O(maxlen). An insert at capacity scans the keys once, which is
at most `maxlen` of them.
"""

from collections import deque
from collections.abc import Callable, Hashable, Iterator


class FairShareHistory[T]:
    """Bounded, insertion-ordered history whose eviction takes from the largest key."""

    def __init__(self, maxlen: int, key: Callable[[T], Hashable]) -> None:
        """`key` names an item's source. It is used when `append` is given no key."""
        if maxlen < 1:
            raise ValueError("maxlen must be at least 1")
        self._maxlen = maxlen
        self._key = key
        self._sequence = 0
        # Insertion-ordered: iterating the dict is iterating chronologically.
        self._items: dict[int, T] = {}
        self._by_key: dict[Hashable, deque[int]] = {}

    @property
    def maxlen(self) -> int:
        return self._maxlen

    def append(self, item: T, key: Hashable | None = None) -> None:
        """Record `item`. `key` overrides the key function, for items that carry no source."""
        resolved = self._key(item) if key is None else key
        if len(self._items) >= self._maxlen:
            self._evict_one()
        self._sequence += 1
        self._items[self._sequence] = item
        self._by_key.setdefault(resolved, deque()).append(self._sequence)

    def _evict_one(self) -> None:
        victim = max(self._by_key, key=lambda k: (len(self._by_key[k]), -self._by_key[k][0]))
        sequences = self._by_key[victim]
        del self._items[sequences.popleft()]
        if not sequences:
            del self._by_key[victim]

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[T]:
        return iter(list(self._items.values()))

    def __getitem__(self, index: int) -> T:
        return list(self._items.values())[index]
