from json import loads, dumps
from errors import *
from controllers.log_controller import *
from controllers.security_controller import DB_FILEPATH, EMPTY_PASS, checkPassword

def getUsers(ld) -> dict:
    database = ld.load()

    user_info = database.copy()
    for i in user_info:
        user_info[i].pop("password")
        if user_info[i]["restricted"]: user_info[i]["restricted"] = "Yes"
        else: user_info[i]["restricted"] = "No"
        if user_info[i]["banned"]: user_info[i]["banned"] = "Yes"
        else: user_info[i]["banned"] = "No"

    return user_info


def updateUser(username:str, restriction, ban, ld) -> dict:
    database = ld.load()
    old_restriction = database[username]["restricted"]
    database[username]["restricted"] = True if restriction == "Yes" else False
    database[username]["force_change_password"] = True if restriction == "Yes" else database[username]["force_change_password"]
    if old_restriction != database[username]["restricted"]:
        log(INFO_LOG, f"User '{username}' restrictions changed to {database[username]["restricted"]}")

    if database[username]["role"] == "admin" and ban == "Yes":
        log(ERR_LOG, f"Attempt to ban admin '{username}' failed. Reason: {ADMIN_BAN_ERR}")
        return {"Error": ADMIN_BAN_ERR}
    old_ban = database[username]["banned"]

    database[username]["banned"] = True if ban == "Yes" else False
    database[username]["inc_att"] = 0 if ban == "No" else database[username]["inc_att"]
    database[username]["force_change_password"] = True if ban == "Yes" else database[username]["force_change_password"]


    if old_ban != database[username]["banned"]:
        log(INFO_LOG, f"User '{username}' ban status changed to {database[username]["banned"]}")

    ld.save(database)
    return username

def createUser(username:str, ld) -> dict:

    if username == "":
        log(ERR_LOG, f"Attempt to create user failed. Reason: {EMPTY_USERNAME_ERR}")
        return {"Error": EMPTY_USERNAME_ERR}

    database = ld.load()

    if username in database:
        log(ERR_LOG, f"Attempt to create user '{username}' failed. Reason: {USERNAME_TAKEN_ERR}")
        return {"Error": USERNAME_TAKEN_ERR}

    database[username] = {"password": EMPTY_PASS, "role": "user", "restricted": False, "force_change_password": True, "banned": False, "inc_att": 0}
    log(INFO_LOG, f"User '{username}' created")
    ld.save(database)

    return {"username": username, "role": database[username]["role"]}

def deleteUser(username:str, password:str, adminname:str, ld) -> dict:
    if checkPassword(adminname, password, ld):
        database = ld.load()

        if username not in database:
            log(ERR_LOG, f"Attempt to delete user '{username}' failed. Reason: {INC_USER_ERR}")
            return {"Error": INC_USER_ERR}

        if database[username]["role"] == "admin":
            log(ERR_LOG, f"Attempt to delete user '{username}' failed. Reason: {ADMIN_DEL_ERR}")
            return {"Error": ADMIN_DEL_ERR}

        del database[username]
        log(INFO_LOG, f"User '{username}' deleted")
        ld.save(database)
        return {"username": username}
    else:
        log(ERR_LOG, f"Attempt to delete user '{username}' failed. Reason: {INC_PASS_ERR}")
        return {"Error": INC_PASS_ERR}