# dpd-uvicorn-runner

Wrapper script for logging with privacy protection features for the FastAPI-based online version of the Digital Pāḷi Dictionary implemented in https://github.com/digitalpalidictionary/dpd-db under `exporter/dpd_fastapi` and running at https://dpdict.net

It has the following features:

- log file rotation:
  - the current log file is `dpd-fastapi.log`
  - older log files have a number appended
  - they are rotated every 30 days (interval configurable)
  - by default 6 log files are kept (number configurable)
- logging of URL-decoded search strings
- IP country lookup:
  - the country of the source IP is logged using an offline data base
- logging of statistics in server-stats.json:
  - logs the number of requests per country
  - the log is updated every 60 minutes (interval configurable) and when the server or wrapper receive SIGINT
  - these counts are continued after server restarts
- IP anonymization:
  - the IP in the log file is anonymized. After each start of the runner a new random key is used and thus the anonymization mapping will change then.
- Search string suppression:
  - If a search string is unlikely to be a query for a Pāḷi word or idiom, it is replaced in the `dpd-fastapi.log` by the rule that was triggered.

