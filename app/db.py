from contextlib import contextmanager
from typing import Iterator
from uuid import UUID
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from .settings import Settings

class VaultDatabase:
    """Synchronous, transaction-scoped database gateway.

    The connection string must point at a private Supabase/Postgres connection,
    never the public PostgREST endpoint. Every multi-step transfer is one SQL tx.
    """
    def __init__(self, settings: Settings):
        self.pool = ConnectionPool(conninfo=settings.database_url, kwargs={"row_factory": dict_row}, open=False)
    def open(self) -> None: self.pool.open()
    def close(self) -> None: self.pool.close()
    @contextmanager
    def transaction(self) -> Iterator:
        with self.pool.connection() as conn:
            with conn.transaction():
                yield conn
    def user_partitions(self, user_id: UUID):
        with self.pool.connection() as conn:
            return conn.execute("""select id,serial_number,denomination,quantity,issued_at,transferred_at
              from terra_partitions where owner_user_id=%s and retired_at is null
              order by issued_at, serial_number""", (user_id,)).fetchall()
