#!/usr/bin/python3
import subprocess
from datetime import datetime
from configparser import ConfigParser
import click
import time
import os
import maxminddb
import re

DEFAULT_CFG = "config.ini"


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


def configure(ctx, param, filename):
    cfg = ConfigParser()
    cfg.read(filename)
    try:
        options = dict(cfg["options"])
    except KeyError:
        options = {}
    ctx.default_map = options


def ip_to_country(ip: str, geolite_db_file_path) -> str:
    result = "unknown"
    with maxminddb.open_database(geolite_db_file_path) as reader:
        json_result = reader.get('152.216.7.110')
        print(json_result)
    return result


def replace_ipv4_addresses_with_geo_country(line: str) -> str:
    match = re.findall(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', line)
    print(match)
    return line


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
@click.option("--port", type=int, default=8080)
def main_function(port):
    """
    Main function
    """
    process = create_process(port)

    # works only on unix:
    os.set_blocking(process.stdout.fileno(), False)
    os.set_blocking(process.stderr.fileno(), False)

    while True:
        stderr = process.stderr.readline()
        stdout = process.stdout.readline()
        if(stderr != ""):
            print(process_log_line(stderr.strip()))
        if(stdout != ""):
            stdout = replace_ipv4_addresses_with_geo_country(stdout)
            print(process_log_line(stdout.strip()))
        if(stdout == "" and stderr == ""):
            time.sleep(1)
        # Do something else
        return_code = process.poll()
        if return_code is not None:
            print("RETURN CODE", return_code)
            # Process has finished, read rest of the output
            for output in process.stderr.readlines():
                print(process_log_line(output.strip()))
            for output in process.stdout.readlines():
                print(process_log_line(output.strip()))
            break


if __name__ == "__main__":
    main_function()
