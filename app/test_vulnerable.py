import os

def login(user_input):
    password = "admin123"
    result = eval(user_input)
    os.system("ls " + user_input)
    return result

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query