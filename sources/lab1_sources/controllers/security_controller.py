from argon2 import PasswordHasher
from json import loads, dumps
from string import ascii_letters, punctuation
from errors import *
from controllers.log_controller import *
from controllers.crypto_controller import *


ARITHM_SYMBOLS = "+-*/^"
EMPTY_PASS = "$argon2id$v=19$m=65536,t=3,p=4$NodMK2Xf9JVoqiDtGECPAA$5RPg74/I5hoSgeeqpgytsIlBWMI0jNZDh80ajBGD8dw"
DB_FILEPATH = 'json/database.json'

class DBLoader:
    def __init__(self, passwd:str, salt:str):
        self.passwd = passwd
        self.salt = salt
        self.db_path = DB_FILEPATH

    def save(self, data:dict) -> None:
        with open(self.db_path, 'wb') as f:
            data = dumps(data)
            data = encrBase(self.passwd, self.salt, data)
            f.write(data)

    def load(self) -> dict:
        with open(self.db_path, 'rb') as f:
            data = f.read()
            data = decrBase(self.passwd, self.salt, data)
            data = loads(data)
        return data

def endSession(ld) -> None:
    database = ld.load()
    database = encrEndBase(ld.passwd, database)
    with open(DB_FILEPATH, 'wb') as f:
        f.write(database)


def initDB(passwd:str, salt:str) -> None:
    try:
        log(INFO_LOG, "Loading database file")
        with open(DB_FILEPATH, 'rb') as f:
            data = f.read()
            data = decrBase(passwd, salt, data)
            data = loads(data)
    except:
        log(INFO_LOG, "Database file not found, creating new one")
        data = {
            "ADMIN": {
                "password": EMPTY_PASS,
                "role": "admin",
                "restricted": False,
                "force_change_password": True,
                "banned": False,
                "inc_att": 0
            }
        }
        with open(DB_FILEPATH, 'wb') as f:
            data = dumps(data)
            data = encrBase(passwd, salt, data)
            f.write(data)

def checkPassword(username:str, password:str, ld) -> bool:
    database = ld.load()

    ph = PasswordHasher()
    stored_password = database[username]["password"]
    try:
        ph.verify(stored_password, password)
    except:
        return False
    return True

def checkLogin(username:str, password:str, ld) -> dict:

    ph = PasswordHasher()

    database = ld.load()

    if username not in database:
        log(ERR_LOG, f"Attemp to login as '{username}' failed. Reason: {INC_USER_ERR}")
        return {"Error": INC_LOGIN_ERR}

    if database[username]["banned"]:
        log(ERR_LOG, f"Attemp to login as '{username}' failed. Reason: {USER_BAN_ERR}")
        return {"Error": USER_BAN_ERR}

    if database[username]["force_change_password"]:
        log(INFO_LOG, f"Attemp to login as '{username}' failed. Reason: {CHANGE_PASS_ERR}")
        user = {"username": username, "role": database[username]["role"]}
        return {"Info": CHANGE_PASS_ERR, "user": user}

    stored_password = database[username]["password"]
    try:
        ph.verify(stored_password, password)
    except:
        error = INC_LOGIN_ERR
        database[username]["inc_att"] += 1
        log(ERR_LOG, f"Attemp to login as '{username}' failed. Reason: {INC_PASS_ERR}")

        if database[username]["inc_att"] >= 3:
            database[username]["banned"] = True
            database[username]["force_change_password"] = True
            error = ATT_BAN_ERR
            log(ERR_LOG, f"User '{username}' banned, reason: {ATT_BAN_ERR}")

        ld.save(database)

        return {"Error": error}

    log(INFO_LOG, f"User '{username}' logged in")
    database[username]["inc_att"] = 0
    ld.save(database)
    return {"username": username, "role": database[username]["role"]}

def checkPasswordRestrictions(password:str) -> bool:
    if (
        any(char in ascii_letters for char in password) and
        any(char in punctuation for char in password) and
        any(char in ARITHM_SYMBOLS for char in password)
    ):
        return True
    return False

def changePassword(old_password:str, new_password:str, user:dict, ld) -> dict:
    database = ld.load()

    if database[user["username"]]["restricted"]:
        if not checkPasswordRestrictions(new_password):
            log(ERR_LOG, f"Attempt to change password for restricted user '{user['username']}' failed. Reason: {PASS_RESRT_ERR}")
            return {"Error": PASS_RESRT_ERR}

    ph = PasswordHasher()



    username = user["username"]
    stored_password = database[username]["password"]
    try:
        ph.verify(stored_password, old_password)
    except:
        log(ERR_LOG, f"Attempt to change password for user '{username}' failed. Reason: {INC_PASS_ERR}")
        return {"Error": INC_PASS_ERR}

    database[username]["password"] = ph.hash(new_password)
    database[username]["force_change_password"] = False
    ld.save(database)

    log(INFO_LOG, f"Password for user '{username}' changed")
    return user