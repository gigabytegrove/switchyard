"""Persistent bounded desktop session metadata, without recordings or secrets."""
from __future__ import annotations

import time
import csv
import io
from datetime import datetime, timezone

MAX_HISTORY = 1000


def initialize(dbconn):
    with dbconn() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS desktop_session_history (
          session_id TEXT PRIMARY KEY,
          desktop_id TEXT NOT NULL,
          label TEXT NOT NULL,
          protocol TEXT NOT NULL,
          started_at INTEGER NOT NULL,
          ended_at INTEGER,
          outcome TEXT NOT NULL CHECK(outcome IN ('opening','open','closed','failed')),
          channel_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS desktop_session_timeline
          ON desktop_session_history(started_at DESC);
        ''')


def started(dbconn, session_id: str, desktop_id: str, label: str, protocol: str):
    with dbconn() as db:
        db.execute('''INSERT INTO desktop_session_history
          (session_id,desktop_id,label,protocol,started_at,ended_at,outcome,channel_count)
          VALUES (?,?,?,?,?,NULL,'opening',0)
          ON CONFLICT(session_id) DO UPDATE SET ended_at=NULL,outcome='opening' ''',
          (session_id,desktop_id,label,protocol,int(time.time())))
        db.execute('''DELETE FROM desktop_session_history WHERE session_id IN (
          SELECT session_id FROM desktop_session_history
          ORDER BY started_at DESC, session_id DESC LIMIT -1 OFFSET ?)''', (MAX_HISTORY,))


def opened(dbconn, session_id: str):
    with dbconn() as db:
        db.execute("UPDATE desktop_session_history SET outcome='open', channel_count=channel_count+1 WHERE session_id=?",
                   (session_id,))


def finished(dbconn, session_id: str, failed: bool = False):
    with dbconn() as db:
        db.execute("""UPDATE desktop_session_history
          SET ended_at=?,outcome=CASE WHEN ? THEN 'failed' ELSE 'closed' END
          WHERE session_id=?""", (int(time.time()),int(failed),session_id))


def list_recent(dbconn, limit: int = 50, protocol: str | None = None,
                outcome: str | None = None):
    clauses = []
    arguments = []
    if protocol:
        clauses.append('protocol=?')
        arguments.append(protocol)
    if outcome:
        clauses.append('outcome=?')
        arguments.append(outcome)
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    arguments.append(max(1, min(limit, 100)))
    with dbconn() as db:
        return [dict(row) for row in db.execute(
            'SELECT * FROM desktop_session_history' + where
            + ' ORDER BY started_at DESC,session_id DESC LIMIT ?', arguments)]


def export_csv(dbconn) -> str:
    """Export bounded, nonsecret session metadata; escape spreadsheet formulas."""
    with dbconn() as db:
        rows = db.execute("""SELECT session_id,desktop_id,label,protocol,started_at,ended_at,outcome,channel_count
          FROM desktop_session_history ORDER BY started_at DESC,session_id DESC LIMIT ?""",
          (MAX_HISTORY,)).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(('session_id','desktop_id','label','protocol','started_at_utc',
                     'ended_at_utc','outcome','channel_count'))
    def safe(value):
        text = str(value)
        return "'" + text if text.lstrip().startswith(('=','+','-','@','\t','\r')) else text
    def timestamp(value):
        return datetime.fromtimestamp(value, timezone.utc).isoformat() if value is not None else ''
    for row in rows:
        writer.writerow((safe(row['session_id']), safe(row['desktop_id']), safe(row['label']),
                         safe(row['protocol']), timestamp(row['started_at']),
                         timestamp(row['ended_at']), safe(row['outcome']), row['channel_count']))
    return output.getvalue()
