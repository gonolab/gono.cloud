#!/bin/sh
# Starts, stops or describes a throwaway MySQL server for the tests that run against MySQL.
#
#   acceptance/scripts/mysql-instance.sh start   # initialize (first time) and start it
#   acceptance/scripts/mysql-instance.sh url     # print the URL for GONO_TEST_MYSQL_URL
#   acceptance/scripts/mysql-instance.sh stop
#
# The server listens on 127.0.0.1 only, its root account has no password, and its data lives in
# the repository's target/ directory (ignored by git), so it never touches another MySQL
# installation on the machine. It is for tests only.
#
# Variables:
#   MYSQL_BASEDIR  installation of MySQL 5.7.44 or later (default: Homebrew's mysql@5.7)
#   MYSQL_DATADIR  data directory (default: <repository>/target/mysql-test)
#   MYSQL_PORT     TCP port (default: 3317)
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
basedir=${MYSQL_BASEDIR:-/opt/homebrew/opt/mysql@5.7}
datadir=${MYSQL_DATADIR:-$root/target/mysql-test}
port=${MYSQL_PORT:-3317}
cnf="$datadir.cnf"
socket="$datadir/mysqld.sock"
pidfile="$datadir/mysqld.pid"

write_cnf() {
    cat >"$cnf" <<EOF
[mysqld]
basedir = $basedir
datadir = $datadir
port = $port
bind-address = 127.0.0.1
socket = $socket
pid-file = $pidfile
log-error = $datadir/mysqld.err
character-set-server = utf8mb4
collation-server = utf8mb4_bin
innodb_file_per_table = 1
innodb_flush_log_at_trx_commit = 2
# Every test creates a database of its own. Keep few table files open: on macOS mysqld waits
# for connections with select(), which fails once a descriptor number reaches FD_SETSIZE (1024),
# and new connections are then dropped.
table_open_cache = 256
table_definition_cache = 512
innodb_open_files = 256
max_connections = 300
# Every connection of every test's pool keeps its prepared statements.
max_prepared_stmt_count = 200000
EOF
}

running() {
    [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

case "${1:-}" in
start)
    if running; then
        echo "MySQL test server already running on 127.0.0.1:$port"
        exit 0
    fi
    mkdir -p "$(dirname "$datadir")"
    write_cnf
    if [ ! -d "$datadir/mysql" ]; then
        "$basedir/bin/mysqld" --defaults-file="$cnf" --initialize-insecure
    fi
    "$basedir/bin/mysqld" --defaults-file="$cnf" --daemonize >/dev/null
    tries=0
    until "$basedir/bin/mysqladmin" -S "$socket" -u root ping >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -gt 60 ]; then
            echo "MySQL test server did not start; see $datadir/mysqld.err" >&2
            exit 1
        fi
        sleep 1
    done
    # --initialize-insecure creates root@localhost only; the tests connect over TCP.
    "$basedir/bin/mysql" -S "$socket" -u root -e \
        "CREATE USER IF NOT EXISTS 'root'@'127.0.0.1';
         GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;"
    echo "MySQL test server running on 127.0.0.1:$port"
    ;;
stop)
    if running; then
        "$basedir/bin/mysqladmin" --protocol=tcp -h 127.0.0.1 -P "$port" -u root shutdown
    fi
    ;;
url)
    echo "mysql://root@127.0.0.1:$port"
    ;;
*)
    echo "usage: $0 start|stop|url" >&2
    exit 2
    ;;
esac
