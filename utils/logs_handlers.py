import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler


# Create a custom handler that extends TimedRotatingFileHandler
class CustomTimedRotatingFileHandler(TimedRotatingFileHandler):

    def __init__(self, dir_log, when='midnight', interval=1, backupCount=0, encoding=None):
        # Base directory for logs
        self.dir_log = os.path.abspath(dir_log)

        # Current log filename
        self.current_logfile = self._get_timed_logfile()

        super().__init__(self.current_logfile, when=when, interval=interval, backupCount=backupCount, encoding=encoding)

    def _get_timed_logfile(self):
        """Generate logfile path based on the current date."""
        current_date = datetime.now()

        # Generating directory structure like /year-month/day.log
        log_dir = os.path.join(self.dir_log, current_date.strftime('%Y-%m'))
        log_file = os.path.join(log_dir, f"{current_date.strftime('%d')}.log")

        # Create directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        return log_file

    def doRollover(self):
        """Overriding to update the current log file path."""
        self.stream.close()
        self.current_logfile = self._get_timed_logfile()
        self.baseFilename = self.current_logfile
        self.mode = 'a'
        self.stream = self._open()


# Configuring the logger
logger = logging.getLogger('my_logger')
logger.setLevel(logging.DEBUG)

handler = CustomTimedRotatingFileHandler(dir_log='./logs', when='midnight', interval=1)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

# Test logging
logger.info("This is a test log")
