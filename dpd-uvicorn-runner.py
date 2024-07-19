#!/usr/bin/python3
import subprocess
from datetime import datetime
from configparser import ConfigParser
import click
import time
import os
import maxminddb
import re
import traceback
from urllib.parse import unquote
import regex
import logging
from logging.handlers import TimedRotatingFileHandler
import hashlib
import ipaddress
import random
import string
from typing import Optional
from stats import ServerStats
from datetime import timedelta
import signal


"""
TODOs:
- [X] logging of anonymized IPs (tracked for some time intervall)
- [ ] catch exception on level of main and write to an exception log (runner will exit, but subprocess will continue)
- [ ] long term stats file:
    - [ ] written at intervals (and also on shutdown)
    - [ ] read in to init the stats when starting up
    - [ ] requests per country for each month
    - [ ] requests / minute
"""

gl_pali_alphabet = "aābcdḍeghiījklḷmṁṃnñṇṅoprṛsṣśtṭuūvy"

DEFAULT_CFG = "config.ini"

SERVER_STATS = ServerStats()

# geo lite db can be downloaded here: https://github.com/P3TERX/GeoLite.mmdb?tab=readme-ov-file
gl_mmdb_file = ""
gl_mmdb_reader = None
gl_logger : Optional[logging.Logger] = None
#gl_exit_requested  : bool = False

gl_country_req_cnt_map: dict[str, int] = {}


RANDOM_STRING_KEY : bytes = "".join(
    random.SystemRandom().choice(string.ascii_letters + string.digits)
    for _ in range(40)
).encode()


# from https://www.finnie.org/2020/09/29/the-perfect-ip-hashing-algorithm/
def hash_ip(ip_str : str, key : bytes) -> str:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as e:
        return "IP conversion error: " + str(e)
    last_len = -8 if ip.version == 6 else -1
    base_bytes = ip.packed[:last_len]
    last_bytes = ip.packed[last_len:]
    base_bhash = hashlib.shake_256(key + base_bytes).digest(len(base_bytes))
    last_bhash = hashlib.shake_256(key + ip.packed).digest(len(last_bytes))
    return str(ipaddress.ip_address(base_bhash + last_bhash))


def create_process(port: int):
    """
    Create the uvicorn process
    """
    return subprocess.Popen(
        [
            "uvicorn",
            "exporter.dpd_fastapi.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )


def make_time_string_now() -> str:
    now = datetime.now()
    date_time = now.strftime("%Y-%m-%d %H:%M:%S")
    return date_time


def process_log_line(line: str) -> str:
    return "[" + make_time_string_now() + "] " + line


def set_gl_geo_lite_db_file(filename):
    global gl_mmdb_file
    gl_mmdb_file = filename


def set_gl_mmdb_db_reader():
    global gl_mmdb_file
    global gl_mmdb_reader
    gl_mmdb_reader = maxminddb.open_database(gl_mmdb_file)


def init_mmdb(filename):
    gl_logger.info("opening mmdb reader")
    set_gl_geo_lite_db_file(filename)
    set_gl_mmdb_db_reader()


def configure(ctx, param, filename):
    cfg = ConfigParser()
    cfg.read(filename)
    try:
        options = dict(cfg["options"])
    except KeyError:
        options = {}
    ctx.default_map = options


def parse_origin_country_from_mmdb_lookup(j: dict, server_stats : ServerStats) -> str:
    country = "<ip-from-co:"
    iso_code = ""
    try:
        country += j["country"]["names"]["en"] + ">"
    except:
        country += "mmdb-lookup-failure>"
    try:
        iso_code = j["country"]["iso"]
    except:
        iso_code = "mmdb-lookup-failure>"
    server_stats.count_country_code(iso_code)
    gl_logger.info("country stats: " + str(gl_country_req_cnt_map))
    return country


def ip_anon_and_to_country(ip: str, server_stats : ServerStats) -> str:
    if gl_mmdb_reader is None:
        raise Exception("mmdb reader not set")
    dict_result = gl_mmdb_reader.get(ip)
    anon_ip = hash_ip(ip, RANDOM_STRING_KEY)
    return anon_ip + ":" + parse_origin_country_from_mmdb_lookup(dict_result, server_stats)


def is_get_request_log_line(line: str) -> bool:
    match = re.match(
        r'.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5} - "GET ', line
    )
    if not match:
        return False
    return True


def replace_ipv4_addresses_with_geo_country(line: str, server_stats : ServerStats) -> str:
    if not is_get_request_log_line(line):
        return line
    match = re.findall(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
    if match:
        anon_ip_with_country = ip_anon_and_to_country(match[0], server_stats)
        return re.sub(pattern=match[0], repl=anon_ip_with_country, string=line)
    return line


def make_url_param_repl_str(explanation: str) -> str:
    return f"REMOVED BY RULE: <{explanation}>"


def list_non_pali_characters_in_str(s: str) -> str:
    res_set: set[str] = set()
    for char in s:
        if char not in gl_pali_alphabet:
            res_set.add(char)
    return "".join(res_set)


def filter_search_str_url_encoded(match_obj: regex.Match) -> str:
    if match_obj:
        s = unquote(match_obj.group(0))
        if s.count(" ") > 0:
            return make_url_param_repl_str("more than one word")
        non_pali_chars: str = list_non_pali_characters_in_str(s)
        if len(non_pali_chars) > 0:
            return make_url_param_repl_str(
                "non-pali character(s) in search string: " + non_pali_chars
            )
        return match_obj.group(0)
    else:
        return "<unexpectedly received empty match obj for search string replacement>"


def filter_search_str_from_get_req_line(line: str) -> str:
    return regex.sub(
        pattern=r"(?<=GET /.*search=)([^ ]+)",
        repl=filter_search_str_url_encoded,
        string=line,
    )
    # return regex.sub(pattern=r'(?<=GET /.*search=)([^ ]+)(?=HTTP/)', repl=filter_search_str_url_encoded, string=line)


def log_server_stats_after_intervall(server_stats : ServerStats, server_stats_intervall_mins : int, server_stats_path, force : bool) -> None:
    now = datetime.now()
    time_for_next_write = timedelta(minutes=server_stats_intervall_mins) + server_stats.get_last_written()
    server_stats.last_written_to_now()
    json_str = str(server_stats)
    if time_for_next_write <= now or force:
       with open(server_stats_path, 'w') as file:
           file.write(json_str)


def create_timed_rotating_log(path, log_rotation_days, log_backup_count):
    global gl_logger
    gl_logger = logging.getLogger("Rotating Log")
    gl_logger.setLevel(logging.INFO)
    gl_logger.setLevel(logging.INFO)
    handler = TimedRotatingFileHandler(path,
                                       when="D",
                                       interval=log_rotation_days,
                                       backupCount=log_backup_count)
    gl_logger.addHandler(handler)
    gl_logger.addHandler(handler)
    gl_logger.info(f"logging started with interval of {log_rotation_days} days")





@click.group(invoke_without_command=True)
@click.option(
    "-c",
    "--config",
    type=click.Path(dir_okay=False),
    default=DEFAULT_CFG,
    callback=configure,
    is_eager=True,
    expose_value=False,
    help="Read option defaults from the specified INI file",
    show_default=True,
)
@click.option(
    "-g",
    "--geo-lite-db-file",
    type=click.Path(dir_okay=False, exists=True),
    default="GeoLite2-Country.mmdb",
    callback=None,
    is_eager=False,
    expose_value=True,
    help="Path to the Geo Lite DB (country) file",
    show_default=True,
)
@click.option(
    "-s",
    "--server-stats-path",
    type=click.Path(dir_okay=False, exists=True),
    default="server-stats.json",
    callback=None,
    is_eager=False,
    expose_value=True,
    help="Path to the server stats file for keeping server statistics over different invocations of the server. The file must exist, but it may be empty to set up a new statistics log.",
    show_default=True,
)
@click.option(
    "-i",
    "--server-stats-intervall-mins",
    type=click.INT,
    default=60,
    callback=None,
    is_eager=False,
    expose_value=True,
    help="Intervall in minutes after which the server-stats file is updated on disk",
    show_default=True,
)
@click.option(
    "-r",
    "--log-rotation-days",
    type=click.INT,
    default=30,
    callback=None,
    is_eager=False,
    expose_value=True,
    help="number of days after which a new log file is created",
    show_default=True,
)
@click.option(
    "-b",
    "--log-backup-count",
    type=click.INT,
    default=6,
    callback=None,
    is_eager=False,
    expose_value=True,
    help="number of old log files to keep",
    show_default=True,
)
@click.option(
    "--port",
    type=int,
    default=8080,
    help="Port on which the uvicorn application will listen.",
)
def main_function(port, geo_lite_db_file, log_backup_count, log_rotation_days, server_stats_path, server_stats_intervall_mins):
    """
    Main function
    """
    exit_requested = False

    def signal_handler_sigint(sig, frame):
        exit_requested = True
        gl_logger.info("received signal SIGINT, exiting")

    signal.signal(signal.SIGINT, signal_handler_sigint)
    create_timed_rotating_log("./dpd-fastapi.log", log_rotation_days, log_backup_count)
    server_stats_str = ""
    with open(server_stats_path, 'r') as file:
        server_stats_str = file.read()
    gl_logger.info("server stats file on disk was" + (": " + server_stats_str) if server_stats_str != "" else " empty")
    server_stats = ServerStats(server_stats_str)
    init_mmdb(geo_lite_db_file)
    process = create_process(port)

    try:
        # works only on unix:
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)

        while True:
            force_server_stats_write = exit_requested
            log_server_stats_after_intervall(server_stats, server_stats_intervall_mins, server_stats_path, force=force_server_stats_write)
            if force_server_stats_write:
                # breaking here ensures we have written the server stats
                break

            stderr = process.stderr.readline()
            stdout = process.stdout.readline()
            if stderr != "":
                stderr = replace_ipv4_addresses_with_geo_country(stderr, server_stats)
                stderr = filter_search_str_from_get_req_line(stderr)
                gl_logger.info(process_log_line(stderr.strip()))
            if stdout != "":
                stdout = replace_ipv4_addresses_with_geo_country(stdout, server_stats)
                stdout = filter_search_str_from_get_req_line(stdout)
                gl_logger.info(process_log_line(stdout.strip()))
            if stdout == "" and stderr == "":
                time.sleep(1)
            # Do something else
            return_code = process.poll()
            if return_code is not None:
                gl_logger.info("exit code of uvicorn process: " + str(return_code))
                # Process has finished, read rest of the output
                for output in process.stderr.readlines():
                    gl_logger.info(process_log_line(output.strip()))
                for output in process.stdout.readlines():
                    gl_logger.info(process_log_line(output.strip()))
                exit_requested = True
    except Exception:
        gl_logger.error(traceback.format_exc())


if __name__ == "__main__":
    main_function()
