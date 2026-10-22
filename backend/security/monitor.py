from collections import defaultdict, deque
from time import time

class Monitor:
    def __init__(self): self.failures = defaultdict(deque)
    def is_limited(self, client: str, limit: int, window: int):
        now=time(); q=self.failures[client]
        while q and now-q[0]>window: q.popleft()
        return len(q)>=limit, len(q)
    def record_failure(self, client: str, limit: int, window: int):
        now = time(); q = self.failures[client]
        while q and now - q[0] > window: q.popleft()
        q.append(now)
        return len(q) >= limit, len(q)

monitor = Monitor()
