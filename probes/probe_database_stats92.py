class probe_database_stats92(PgProbe):
    level = 'cluster'
    min_version = 902
    max_version = None
    sql = """SELECT date_trunc('seconds', current_timestamp) as datetime,
      datname, numbackends,  xact_commit, xact_rollback, blks_read, blks_hit,
      tup_returned, tup_fetched,  tup_inserted, tup_updated, tup_deleted,
      conflicts, temp_files, temp_bytes, deadlocks, blk_read_time,
      blk_write_time, pg_database_size(datid) AS size
    FROM pg_stat_database"""
