#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2014 Nicolas Thauvin. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


import sys, os, re, signal
import getopt
import logging
import ConfigParser
import imp
import time
from StringIO import StringIO
import urllib
import json

# Globals
probes_path = [ os.path.expanduser('~/.probes'),
                # relative to the script
                os.path.abspath(os.path.dirname(sys.argv[0])) + '/probes',
                '/usr/share/probes-runner/probes' ]

# probes is the base class for all plugins
class Probe(object):
    """Base class for all plugins."""
    # At which level the information is gathered: host, cluster or db
    level = None
    # Optionnal name of the probe
    name = None 

    def check(self):
        """Check if the plugin can run on the target."""
        pass

    def prepare(self):
        """Get ready for many runs."""
        pass

    def run(self):
        """Returns the result."""
        pass

    def get_name(self):
        """Computes the name of the probe."""
        # Let the plugin overwrite the name
        if self.name is not None:
            return self.name

        # Compute the name from the class of the plugin
        m = re.search(r'^probe_(\w+)$', self.__class__.__name__.lower())
        if m is not None:
            return m.group(1)

        logging.error("Could not get the name of the probe")
        return None

    def __repr__(self):
        return self.get_name()

# system probe base class
class SysProbe(Probe):
    level = 'host'
    system = None # kernel name from os.uname()[0]
    min_version = None
    max_version = None

    def check(self):
        """Check if the probe can run on this system."""
        if self.system is not None:
            if self.system != os.uname()[0]:
                return False

        version = [ int(x) for x in re.sub(r'-.*$', '', os.uname()[2]).split('.') ]
        if self.min_version is not None:
            if version[0:len(self.min_version)] < self.min_version:
                return False

        if self.max_version is not None:
            if version[0:len(self.max_version)] > self.max_version:
                return False

        return True

# postgres probe base class
class PgProbe(Probe):
    min_version = None
    max_version = None
    sql = None
        
    def check(self, version=None):
        """Check if the plugin can run on the target version of PostgreSQL."""
        if version is None:
            return False
        
        if self.min_version is not None:
            if version < self.min_version:
                return False

        if self.max_version is not None:
            if version > self.max_version:
                return False

        return True

    def run(self, conn):
        """Get the result of the SQL query of the plugin as CSV."""
        if self.sql is None:
            return ""
        
        cur = conn.cursor()
        buf = StringIO()
        cur.copy_expert("COPY (%s) TO STDOUT CSV;" % self.sql, buf)
        output = buf.getvalue()
        buf.close()

        cur.close()
        return output

# Bundled System probes
class probe_sysinfo(SysProbe):
    system = 'Linux'

    def run(self):
        """Gather information in this box."""
        kernel, node, version, extra, arch = os.uname()
        sysinfo = { "host": node, "kernel": kernel, "version": version,
                    "architecture": arch }

        # use lscpu to get most of the information
        import subprocess
        lscpu = subprocess.Popen("/usr/bin/lscpu", stdout=subprocess.PIPE)
        try:
            out = lscpu.communicate()[0]
            if lscpu.returncode == 0:
                # Parse output
                for line in out.splitlines():
                    m = re.match(r'CPU\(s\):\s+(\d+)$', line)
                    if m:
                        sysinfo["cpu_number"] = m.group(1)
                    
                    m = re.match(r'Socket\(s\):\s+(\d+)$', line)
                    if m:
                        sysinfo["cpu_sockets"] = m.group(1)

                    m = re.match(r'Core\(s\) per socket:\s+(\d+)$', line)
                    if m:
                        sysinfo["cpu_cores"] = m.group(1)

                    m = re.match(r'Thread\(s\) per core:\s+(\d+)$', line)
                    if m:
                        sysinfo["cpu_threads"] = m.group(1)

                    m = re.match(r'CPU MHz:\s+(\d+)[\.\d]*$', line)
                    if m:
                        sysinfo["cpu_frequency"] = m.group(1)
            else:
                logging.warning("lscpu failed: %d", lscpu.returncode)
                               
        except OSError, e:
            logging.error("[sysinfo] Could not run lscpu: %s", str(e))

        # get the model name string from /proc/cpuinfo
        cpuinfo = open("/proc/cpuinfo")
        m = re.search(r'^model name\s+:\s+(.+)$', cpuinfo.read(), re.M)
        if m:
            sysinfo["cpu_model"] = m.group(1)
        cpuinfo.close()

        # Memory
        free = subprocess.Popen(["free", "-k"], stdout=subprocess.PIPE)
        try:
            out = free.communicate()[0]
            if free.returncode == 0:
                # total memory is the second column of the second line
                sysinfo["memory_size"] = out.splitlines()[1].split()[1]
                
                # total swap is the second column of the fourth line
                sysinfo["swap"] = out.splitlines()[3].split()[1]
            else:
                logging.warning("[sysinfo] free -k failed: %d", free.returncode)
        except OSError, e:
            logging.error("[sysinfo] Could not run free: %s", str(e))

        # Filesystems
        df = subprocess.Popen(["df", "-k"], stdout=subprocess.PIPE)
        dfmap = {}
        try:
            out = df.communicate()[0]
            if df.returncode == 0:
                for l in out.splitlines()[1:]:
                    # hash on "mount point" -> "size"
                    dfmap[l.split()[5]] = l.split()[1]
            else:
                logging.warning("[sysinfo] df -k failed: %d", df.returncode)
        except OSError, e:
            logging.error("[sysinfo] Could not run df: %s", str(e))

        mount = subprocess.Popen("mount", stdout=subprocess.PIPE)
        fs = []
        try:
            out = mount.communicate()[0]
            if mount.returncode == 0:
                # build a list of dicts
                for l in out.splitlines():
                    c = l.split()
                    m = re.match(r'^/dev/', c[0])
                    if m:
                        fs.append({"device": c[0], "fstype": c[4],
                                   "mount_point": c[2], "mount_options": c[5][1:-1],
                                   "size": dfmap[c[2]]})
            else:
                logging.warning("[sysinfo] mount failed: %d", mount.returncode)
        except OSError, e:
            logging.error("[sysinfo] Could not run mount: %s", str(e))
        sysinfo["fs"] = fs

        logging.debug("[sysinfo] sysinfo: %r", sysinfo)

        return sysinfo


# Bundled PostgreSQL probes
class probe_database_stats83(PgProbe):
    level = 'cluster'
    min_version = 803
    max_version = 900
    sql = """SELECT date_trunc('seconds', current_timestamp) as datetime,
      datname, numbackends,  xact_commit, xact_rollback, blks_read, blks_hit,
      tup_returned, tup_fetched,  tup_inserted, tup_updated, tup_deleted,
      pg_database_size(datid) AS size
    FROM pg_stat_database"""

class probe_database_stats91(PgProbe):
    level = 'cluster'
    min_version = 901
    max_version = 901
    sql = """SELECT date_trunc('seconds', current_timestamp) as datetime,
      datname, numbackends,  xact_commit, xact_rollback, blks_read, blks_hit,
      tup_returned, tup_fetched,  tup_inserted, tup_updated, tup_deleted,
      conflicts, pg_database_size(datid) AS size
    FROM pg_stat_database"""

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

class probe_tables_stats(PgProbe):
    level = 'db'
    min_version = 803
    max_version = None
    sql = """SELECT date_trunc('seconds', current_timestamp) as datetime,
      schemaname, relname, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch,
      n_tup_ins, n_tup_upd, n_tup_del, n_tup_hot_upd, n_live_tup, n_dead_tup,
      last_vacuum, last_autovacuum, last_analyze, last_autoanalyze
    FROM pg_stat_user_tables"""


# plugins functions
def load_probes(names):
    probes = []
    logging.debug("Probes to load: %s", ", ".join(names))

    for n in names:
        # Every probe file must start with "probe_"
        probe = "probe_" + n

        try:
            fd, pathname, description = imp.find_module(probe, probes_path)
            fd.close()

            # Since our plugins are subclasses of 'probe', we cannot
            # use imp.load_module() because the parent classes would
            # not be found in the namespace of the module. So we
            # execute the contents of the plugin directly.
            execfile(pathname, globals(), locals())

            # We only need an object: remove the class to avoid
            # conflicts after we got it.
            po = eval(probe + "()")
            probes.append(po)
            
            logging.info("Loaded probe from plugin: %s", po.get_name())

            # Skip the eval of the bundled probe
            continue

        except ImportError:
            logging.warning("Probe '%s' not found", n)

        # When the probe is not found try to create an object from a
        # local class. This allow to overwrite probes bundled in this
        # script with plugins
        if probe in globals().keys():
            po = eval(probe + "()")
            probes.append(po)

            logging.info("Loaded probe: %s", po.get_name())

    return probes


def find_all_probes(dirs):
    """Search the dirs for plugin files."""
    probes = []

    # Search the given list of directory for files matching plugin
    # name pattern ("probe_<name>.py")
    r = re.compile(r'^probe_(\w+)\.py$')
    for d in dirs:
        try:
            for f in os.listdir(d):
                m = r.search(f)
                if m is not None:
                    probes.append(m.group(1))
        except OSError, e:
            pass

    # Append all bundled probes to the list
    r = re.compile(r'^probe_(\w+)$')
    for v in globals().keys():
        m = r.search(v)
        if m is not None:
            probes.append(m.group(1))

    # Deduplicate the result
    return list(set(probes))


# database related functions
def prepare_sql_run(probes, conninfos):
    """Try database connections and check if probes can run on them."""

    # Connections are necessary only if we have sql probes to run
    has_sql = False
    for p in probes:
        if isinstance(p, PgProbe):
            has_sql = True
            break
    if not has_sql:
        logging.info("No probes require connections to PostgreSQL")
        return []

    # psycopg2 is the only non standard module we need
    try:
        import psycopg2
        global psycopg2
    except ImportError:
        logging.error("The psycopg2 module is required to access PostgreSQL. SQL probes won't be run.")
        return []

    # Build a list of dicts with connection information
    conns = []
    for cluster in conninfos:
        # Prepare a common dsn from the cluster information
        dsn = ''
        for param in cluster.keys():
            if param == "dbnames" or param == "cluster":
                continue
            if cluster.get(param) is not None:
                dsn += "%s=%s " % (param, cluster[param])

        # Use a flag to limit cluster level probes to the first
        # database
        allow_cluster_level = True

        # Many databases can be probed, create a connection dict fot
        # each of them and test the connection
        for db in cluster['dbnames']:
            conn = {}
            if not db: continue

            conn['cluster'] = cluster['cluster']
            conn['db'] = db
            conn['dsn'] = dsn + "dbname=%s" % db
            conn['probes'] = []
            dbconn = None
            try:
                dbconn = psycopg2.connect(conn['dsn'])
                dbconn.autocommit = True

                # Get the version of the server, only the major part
                # is necessary for plugins.
                cur = dbconn.cursor()
                cur.execute("SELECT setting FROM pg_settings WHERE name = 'server_version'")
                conn['cluster_version'] = cur.fetchone()[0]
                cur.execute("SELECT setting FROM pg_settings WHERE name = 'port'")
                conn['port'] = int(cur.fetchone()[0])
                cur.execute("SELECT current_user")
                conn['username'] = cur.fetchone()[0]
                cur.close()
                
                version = dbconn.server_version / 100
                conn['cluster_version_major_num'] = version
                for p in probes:
                    if isinstance(p, PgProbe) and p.check(version) and ((p.level == "cluster" and allow_cluster_level) or p.level == "db"):
                        conn['probes'].append(p)
                if not conn['probes']:
                    logging.info('No suitable probe(s) found for [%s] %s',
                                 conn['cluster'], conn['db'])
                    continue

                allow_cluster_level = False
            
            except psycopg2.OperationalError, e:
                logging.warning("Could not check connection to [%s] %s",
                                conn['cluster'], conn['db'])
                for l in str(e).splitlines():
                    logging.warning(l)
                continue
            
            except psycopg2.Error, e:
                logging.warning("Could not check connection to [%s] %s: %s",
                                conn['cluster'], conn['db'], e.pgerror)
                continue
            
            finally:
                if dbconn is not None:
                    dbconn.close()

            conns.append(conn)

    [ logging.debug("Usable connection: %r", c) for c in conns ]
    
    return conns

def prepare_sys_run(probes):
    """Check if system probes can run on this host."""
    runables = []
    for po in probes:
        if isinstance(po, SysProbe):
            if po.check():
                runables.append(po)
            else:
                logging.info("Excluded system probe %s", str(po))

    return runables


def sql_run(dbinfos):
    """Run matching probes on given databases."""
    output = {} # dict of clusters
    for dbinfo in dbinfos:
        # init the dict of databases
        if not output.get(dbinfo['cluster']):
            output[dbinfo['cluster']] = {}
        # dict of probes key -> result
        output[dbinfo['cluster']][dbinfo['db']] = {}

        # Run all probes on the same database connection
        try:
            dbconn = psycopg2.connect(dbinfo['dsn'])
                
        except psycopg2.OperationalError, e:
            logging.error("Could not connect to \"%s\"", dbinfo['dsn'])
            for l in str(e).splitlines():
                logging.error(l)
            continue

        dbconn.autocommit = True

        try:
            for p in dbinfo['probes']:
                probe_key = p.get_name()
                result = p.run(dbconn)
                output[dbinfo['cluster']][dbinfo['db']][probe_key] = result

        except psycopg2.Error, e:
            logging.warning("Could not run probe %s on [%s] %s: %s",
                            str(p), dbinfo['cluster'], dbinfo['db'], e.pgerror)
            continue
            
        finally:
            dbconn.close()
            
    return output


def sys_run(probes):
    """Run matching probes on the host system."""
    output = {} # dict of probe names
    for po in probes:
        probe_key = po.get_name()
        output[probe_key] = po.run()

    return output

# output functions
class OutputEncoder(json.JSONEncoder):
    """Tell json that probe objects should be encoded as strings using their
    name.
    """
    def default(self, obj):
        if isinstance(obj, Probe):
            return repr(obj)
        return json.JSONEncoder.default(self, obj)

def clean_conninfos(conns):
    """Remove password from the dsn."""
    connections = [dict(x) for x in conns]
    for c in connections:
        c['dsn'] = re.sub(r"password=('(\\'|[\w\s])*'|\w*)\s?", '', c['dsn']).strip()
    return connections

def send_output(url, key, output):
    """Send data to the target URL."""
    
    data = { "key": key,
             "data": json.dumps(output, cls=OutputEncoder) }
    try:
        r = urllib.urlopen(url, urllib.urlencode(data))
        if hasattr(r, 'getcode'):
            if r.getcode() != 200:
                logging.error("Could not send output to %s: %d", url, r.getcode())
    except IOError, e:
        logging.error("Could not send output to %s %s", url, str(e))



# daemon related functions
def write_pid(pid, pidfile):
    logging.debug("PID: %d, file: %s", pid, pidfile)
    try:
        fd = open(pidfile, 'w')
    except IOError, e:
        logging.error("Could not open %s: %s", pidfile, str(e))
        return False

    fd.write("%d\n" % pid)
    fd.close()
    return True


def signal_handler(signum, frame):
    global pidfile
    # Term
    if signum == 15:
        try:
            if os.path.exists(pidfile):
                logging.debug("Removing pidfile %s" % pidfile)
                os.remove(pidfile)
        except Exception, e:
            logging.error(str(e))
            
        # Close the log file before exiting
        logging.info("Received the TERM signal, exiting")
        logging.shutdown()

        sys.exit(0)


def daemonize(pidfile):
    """Become a background process."""

    # Check the pidfile
    if os.path.exists(pidfile):
        f = open(pidfile)
        pid = int(f.readline().rstrip())
        f.close()
        try:
            if os.kill(pid, 0) is None:
                print >>sys.stderr, "ERROR: another instance is running (%d)" % pid
                sys.exit(1)
        except OSError:
            print >>sys.stderr, "WARNING: stale pidfile found, cleaning"
            os.remove(pidfile)


    # Fork and exit parent
    logging.debug("Forking to background")
    if os.fork():
        sys.exit(0)

    # Decouple by closing stdio fds and becoming session leader
    sys.stdin.close()
    sys.stdout.close()
    sys.stderr.close()
    os.setsid()

    # Fork a second time to forbid reattaching a tty
    if os.fork():
        sys.exit(0)

    if not write_pid(os.getpid(), pidfile):
        logging.error("Could not write pidfile, aborting")
        sys.exit(1)

    # Setup the signal handler
    signal.signal(signal.SIGTERM, signal_handler)


def setup_logger(logfile=None, daemon=True, verbose=False):
    loglevel = logging.INFO
    if verbose:
        loglevel = logging.DEBUG

    if daemon:
        # Everything must go to our log file when running in the background
        try:
            logging.basicConfig(level=loglevel,
                                format='%(asctime)s %(levelname)s: %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S',
                                filename=logfile,
                                filemode='a')
        except Exception, e:
            sys.stderr.write("ERROR: Could not initialize logging.", str(e))
            sys.exit(1)
    else:
        # Leave destination to stderr when running in the foreground
        logging.basicConfig(level=loglevel,
                            format='%(asctime)s %(levelname)s: %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')


# Startup functions
def usage(exit_code):
    print "usage: %s [options] [start|stop|reload]" % os.path.basename(sys.argv[0])
    print """options:
  -c, --config=FILE        configuration file

  -i, --interval=SECONDS   probing time interval in seconds
  -F, --foreground         do not detach from console
  -f, --pid-file=FILE      path to the pid file

  -v, --verbose            print lots of messages
  -h, --help               print usage
  """
    sys.exit(exit_code)

def cli_options():
    """Get the commandline options."""
    
    # Prepare the default options
    options = {'configfile': 'probes-runner.conf',
               'pidfile': '/tmp/probes-runner.pid',
               'daemon': True,
               'debug': False
               }

    # Get what on the command line
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "c:i:Ff:vh",
                                   ["config=", "interval=", "foreground",
                                    "pid-file=", "verbose", "help"])
    except getopt.GetoptError, e:
        sys.stderr.write("ERROR: %s " % str(e))
        usage(2)

    for opt, arg in opts:
        if opt in ("-c", "--config"):
            options['configfile'] = arg
        if opt in ("-i", "--interval"):
            try:
                options['interval'] = int(arg)
            except ValueError:
                sys.stderr.write("WARNING: bad interval value: %r. Skipped.\n" % arg)
        if opt in ("-F", "--foreground"):
            options['daemon'] = False
        if opt in ("-f", "--pid-file"):
            options['pidfile'] = arg
        if opt in ("-v", "--verbose"):
            options['debug'] = True
        if opt in ("-h", "--help"):
            usage(0)

    return options

def read_config_file(path):
    """Update the config dict with a config file."""
    
    # Prepare the default options
    defaults = {'interval': '60',
                'logfile': '/tmp/probes-runner.log',
                }
    options = {}
    
    config = ConfigParser.SafeConfigParser(defaults)

    if not config.read(path):
        # ConfigParser wants the defaults to be strings, some option
        # values must casted to int
        defaults['interval'] = int(defaults['interval'])
        return defaults

    try:
        options['interval'] = config.getint('main', 'interval')
    except ValueError:
        sys.stderr.write("ERROR: Invalid value for main.interval in config")
        pass
    
    options['logfile'] = config.get('main', 'logfile')

    # Get the list of plugins
    try:
        options['probes'] = re.split(r'[,\s]+', config.get('main', 'probes'))
    except ConfigParser.NoOptionError:
        pass

    # collector coordinates
    for o in 'url', 'key':
        try:
            options[o] = config.get('collector', o)
        except ConfigParser.NoSectionError:
            pass
        except ConfigParser.NoOptionError:
            pass

    # The other sections are database cluster informations
    options['conninfo'] = []
    for sect in config.sections():
        if sect == "main" or sect == "collector":
            continue
        try:
            conninfo = {}
            for opt in config.options(sect):
                if opt == "host":
                    conninfo['host'] = config.get(sect, opt)
                if opt == "port":
                    conninfo['port'] = config.getint(sect, opt)
                if opt == "user":
                    conninfo['user'] = config.get(sect, opt)
                if opt == "password":
                    conninfo['password'] = config.get(sect, opt)
                if opt == "dbnames":
                    conninfo['dbnames'] = re.split(r'[,\s]+',
                                                   config.get(sect, opt))

            # the names of database to probe are mandatory
            if 'dbnames' not in conninfo.keys():
                sys.stderr.write("WARNING: cluster [%s] has no databases, see option 'dbnames'\n" % sect)
                continue

            # The section is the cluster name, keep it around
            conninfo['cluster'] = sect

            options['conninfo'].append(conninfo)
        except ValueError:
            # Skip the entire cluster
            sys.stderr.write("WARNING: syntax error in section [%s] of the config\n" % sect)
            pass

    return options

    
def main():
    """Starts the program."""
    
    # Get what on the command line
    cli_opts = cli_options()
    
    # Get the content of the configuration file
    config_opts = read_config_file(cli_opts['configfile'])
    
    # Merge config file and command line options
    options = config_opts
    for o in cli_opts.keys():
        options[o] = cli_opts[o]

    # when running in the background, the signal handler must be able
    # to remove the pidfile
    global pidfile
    pidfile = options['pidfile']

    # Setup the logger
    setup_logger(options['logfile'], options['daemon'], options['debug'])

    # Before loading all the required plugins, check if we have
    # something to load and run.
    if 'probes' not in options.keys():
        logging.error("No probes to run. Aborting.")
        sys.exit(1)
    elif not options['probes'][0]:
        logging.error("No probes to run. Aborting.")
        sys.exit(1)
    else:
        #  One can ask to use every possible probe with *
        for p in options['probes']:
            if p == '*':
                options['probes'] = find_all_probes(probes_path)
                break

    probes = load_probes(options['probes'])

    # Group probes by database connections
    connections = prepare_sql_run(probes, options['conninfo'])

    # Ensure we only run system probes targetted to this OS
    sys_probes = prepare_sys_run(probes)

    # Go to the background
    if options['daemon']:
        daemonize(pidfile)

    # Prepare mandatory data we need to send so that the collector can
    # connect the dots
    hostname = os.uname()[1]
    conninfos = clean_conninfos(connections)

    while True:
        # Gather information by running all probes
        output = {}
        output['host'] = hostname
        output['conninfos'] = conninfos
        output['clusters'] = sql_run(connections)
        output['system'] = sys_run(sys_probes)

        # Send the result to the url of the collector
        send_output(options['url'], options['key'], output)

        logging.debug("Sleeping %d seconds", options['interval'])
        time.sleep(options['interval'])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

