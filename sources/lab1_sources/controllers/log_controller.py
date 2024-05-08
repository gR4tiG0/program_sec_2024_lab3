from json import loads, dumps, JSONDecodeError
import datetime


ERR_LOG = "Error"
INFO_LOG = "Info"
DEBUG_LOG = "Debug"

LOG_FILE_PATH = "json/logs.json"

def log(log_type:str, message:str) -> None:
    try:
        with open(LOG_FILE_PATH, 'r') as f:
            logs = loads(f.read())
    except Exception:
        logs = []

    log = {
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": log_type,
        "message": message
    }
    logs.append(log)
    with open(LOG_FILE_PATH, 'w') as f:
        f.write(dumps(logs))

def getLogs() -> list:
    try:
        with open(LOG_FILE_PATH, 'r') as f:
            logs = loads(f.read())
    except JSONDecodeError:
        logs = []

    return logs[::-1]