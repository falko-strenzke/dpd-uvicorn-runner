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

"""
TODOs:
- [ ] logging of anonymized IPs (tracked for some time intervall)
- [ ] catch exception on level of main and write to an exception log (runner will exit, but subprocess will continue)
"""

gl_pali_alphabet = "aābcdḍeghiījklḷmṁṃnñṇṅoprṛsṣśtṭuūvy"

DEFAULT_CFG = "config.ini"

# geo lite db can be downloaded here: https://github.com/P3TERX/GeoLite.mmdb?tab=readme-ov-file
gl_mmdb_file = ""
gl_mmdb_reader = None
gl_logger = None

gl_country_req_cnt_map : dict[str, int] = {}


def create_process(port : int):
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


def parse_origin_country_from_mmdb_lookup(j : dict) -> str:
    country = "<ip-from-co:"
    try:
        country += j['country']['names']['en'] + ">"
    except:
        country += 'mmdb-lookup-failure>'
    return country


def ip_to_country(ip: str) -> str:
    if gl_mmdb_reader is None:
        raise Exception("mmdb reader not set")
    dict_result = gl_mmdb_reader.get(ip)
    return parse_origin_country_from_mmdb_lookup(dict_result)


def is_get_request_log_line(line : str) -> bool:
    match = re.match(r'.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5} - "GET ', line)
    if not match:
        return False
    return True


def replace_ipv4_addresses_with_geo_country(line: str) -> str:
    if not is_get_request_log_line(line):
        return line
    match = re.findall(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', line)
    if match:
        country = ip_to_country(match[0])
        return re.sub(pattern=match[0], repl=country, string=line)
    return line


def make_url_param_repl_str(explanation : str) -> str:
    return f"REMOVED BY RULE: <{explanation}>"


def list_non_pali_characters_in_str(s : str) -> str:
    res_set : set[str] = set()
    for char in s:
        if char not in gl_pali_alphabet:
            res_set.add(char)
    return "".join(res_set)



def filter_search_str_url_encoded(match_obj: regex.Match) -> str:
    if match_obj:
        s = unquote(match_obj.group(0))
        if s.count(" ") > 0:
            return make_url_param_repl_str("more than one word")
        non_pali_chars : str = list_non_pali_characters_in_str(s)
        if len(non_pali_chars) > 0:
            return make_url_param_repl_str("non-pali character(s) in search string: " + non_pali_chars)
        return match_obj.group(0)
    else:
        return '<unexpectedly received empty match obj for search string replacement>'


def filter_search_str_from_get_req_line(line : str) -> str:
    return regex.sub(pattern=r'(?<=GET /.*search=)([^ ]+)', repl=filter_search_str_url_encoded, string=line)
    return regex.sub(pattern=r'(?<=GET /.*search=)([^ ]+)(?=HTTP/)', repl=filter_search_str_url_encoded, string=line)


def create_timed_rotating_log(path, log_rotation_days, log_backup_count):
    """"""
    global gl_logger
    gl_logger = logging.getLogger("Rotating Log")
    gl_logger.setLevel(logging.INFO)
    handler = TimedRotatingFileHandler(path,
                                       when="D",
                                       interval=log_rotation_days,
                                       backupCount=log_backup_count)
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
    type=click.Path(dir_okay=False),
    default="GeoLite2-Country.mmdb",
    callback=None,
    is_eager=False,
    expose_value=True,
    help="configure the Geo Lite DB",
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
@click.option("--port", type=int, default=8080, help="Port on which the uvicorn application will listen.")
def main_function(port, geo_lite_db_file, log_backup_count, log_rotation_days):
    """
    Main function
    """
    log_file = "dpd-fastapi.log"
    create_timed_rotating_log(log_file, log_rotation_days, log_backup_count)
    init_mmdb(geo_lite_db_file)
    process = create_process(port)

    try:
        # works only on unix:
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)

        while True:
            stderr = process.stderr.readline()
            stdout = process.stdout.readline()
            if stderr != "":
                stderr = replace_ipv4_addresses_with_geo_country(stderr)
                stderr = filter_search_str_from_get_req_line(stderr)
                gl_logger.info(process_log_line(stderr.strip()))
            if stdout != "":
                stdout = replace_ipv4_addresses_with_geo_country(stdout)
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
                break
    except Exception:
        gl_logger.error(traceback.format_exc())


if __name__ == "__main__":
    main_function()
