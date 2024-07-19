
import json
from datetime import datetime


class ServerStats:

    def __init__(self, json_str : str = ""):
        self.date_time_format = '%a %B %d %H:%M:%S %Y'
        if json_str == "":
            self.stats_start_time = datetime.now()
            self.last_written = datetime.now()
            self.country_request_counts : dict[str, int] = {}
            return
        stats_dict : dict = json.loads(json_str)
        self.last_written = datetime.strptime(stats_dict["last-written"], self.date_time_format)
        self.stats_start_time = datetime.strptime(stats_dict["stats-start-time"], self.date_time_format)
        self.country_request_counts = stats_dict["country-request-counts"]

    def __str__(self) -> str:
        last_written_str = self.last_written.strftime(self.date_time_format)
        stats_start_time_str = self.stats_start_time.strftime(self.date_time_format)
        result_str = {'last-written': last_written_str, 'stats-start-time': stats_start_time_str, 'country-request-counts' : self.country_request_counts }
        return json.dumps(result_str)

    def count_country_code(self, country_code : str) -> None:
        count = self.country_request_counts.get(country_code, 0)
        self.country_request_counts[country_code] = count + 1

    def last_written_to_now(self) -> None:
        self.last_written = datetime.now()

    def get_last_written(self) -> datetime:
        return self.last_written
