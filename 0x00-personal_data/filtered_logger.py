#!/usr/bin/env python3
"""A module for filtering logs
"""
import os
import re
import logging
import mysql.connector
from typing import List


patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str,
        ) -> str:
    """
    Filters a log line by redacting specified fields.

    Args:
        fields (List[str]): List of field names to redact.
        redaction (str): The string to replace the sensitive information with.
        message (str): The log message containing sensitive information.
        separator (str): The separator used in the log message.

    Returns:
        str: The log message with sensitive information redacted.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """
    Creates and configures a logger for logging user data.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establishes a connection to the MySQL database using environment variables.

    Returns:
        mysql.connector.connection.MySQLConnection:
        Database connection instance.
    """
    try:
        # Obtain database credentials from environment variables
        db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
        db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
        db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
        db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")

        # Connect to the database
        connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
        )

        if connection.is_connected():
            print("Connected to the database")
            return connection

    except Error as e:
        print(f"Error while connecting to MySQL: {e}")
        return None


def main():
    """
    Fetches user records from the database and logs the information.

    Connects to the database, fetches user records from the 'users' table,
    and logs each record with sensitive information redacted.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """
    Custom logging formatter to redact sensitive information from log messages.

    Attributes:
        REDACTION (str): The string used to replace sensitive information.
        FORMAT (str): The log message format.
        SEPARATOR (str): The separator used in the log message.
        fields (List[str]): List of fields to redact.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """formats a LogRecord.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


if __name__ == "__main__":
    main()
