"""Single-host durable admission cap. Charges before protected model access.

The scope is trusted custodian configuration, shared across program aliases.
This bounds admission count; it does not repair v1 outcome/timing channels.
SQLite transactions prevent concurrent overspend. Host rollback is out of scope.
"""
from pathlib import Path
import sqlite3


class AdmissionBudget:
    def __init__(self, path, scope, cap):
        if type(scope) is not str or not scope or len(scope)>256 or type(cap) is not int or not 1<=cap<=1000000:
            raise ValueError("invalid_budget_configuration")
        self.path, self.scope, self.cap = str(Path(path)), scope, cap
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        with sqlite3.connect(self.path,timeout=30) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("CREATE TABLE IF NOT EXISTS budgets(scope TEXT PRIMARY KEY, cap INTEGER NOT NULL, used INTEGER NOT NULL)")
            connection.execute("INSERT OR IGNORE INTO budgets VALUES (?, ?, 0)",(scope,cap))
            stored = connection.execute("SELECT cap FROM budgets WHERE scope=?",(scope,)).fetchone()[0]
            if stored != cap:
                raise ValueError("budget_cap_mismatch")

    def reserve(self):
        """One committed, non-refundable access slot; failures consume it too."""
        with sqlite3.connect(self.path,timeout=30) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            cap,used = connection.execute("SELECT cap,used FROM budgets WHERE scope=?",(self.scope,)).fetchone()
            if cap!=self.cap or not 0<=used<=cap:
                raise ValueError("invalid_budget_state")
            if used==cap:
                return False
            connection.execute("UPDATE budgets SET used=used+1 WHERE scope=?",(self.scope,))
            return True

    def consumed(self):
        with sqlite3.connect(self.path,timeout=30) as connection:
            return connection.execute("SELECT used FROM budgets WHERE scope=?",(self.scope,)).fetchone()[0]
