class probe_database_stats83(PgProbe):
    level = 'cluster'
    min_version = 803
    max_version = 900
    sql = """SELECT date_trunc('seconds', current_timestamp) as datetime,
      datname, numbackends,  xact_commit, xact_rollback, blks_read, blks_hit,
      tup_returned, tup_fetched,  tup_inserted, tup_updated, tup_deleted,
      pg_database_size(datid) AS size
    FROM pg_stat_database"""
