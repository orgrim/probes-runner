class probe_tables_stats(PgProbe):
    level = 'db'
    min_version = 803
    max_version = None
    sql = """SELECT date_trunc('seconds', current_timestamp) as datetime,
      schemaname, relname, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch,
      n_tup_ins, n_tup_upd, n_tup_del, n_tup_hot_upd, n_live_tup, n_dead_tup,
      last_vacuum, last_autovacuum, last_analyze, last_autoanalyze
    FROM pg_stat_user_tables"""
