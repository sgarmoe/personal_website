"""main python file to run html site thru flask"""
#Samuel Garmoe
#SDEV 300
#May 6th, 2024


import re
import cgi
from datetime import datetime
from flask import Flask, url_for
from flask import render_template, request
from passlib.hash import sha256_crypt

#constants, arrays, and file names
app = Flask(__name__, static_folder='static') #initializing flask instance
users = {} #database for storing user registration
filename = 'users.txt' #file for user and pw storage
common_pws = {}
common_pws_file = 'CommonPassword.txt'
form = cgi.FieldStorage()
login_counter = 0
LOG_FILE = 'login_attempts.log'


if __name__ == '__main__':
    app.run(debug=True)

def main():
    """run main function"""
    main()


#route for registering a user; HOME PAGE when going to site
@app.route('/', methods=["GET", "POST"])
def register():
    """default page. user registers for site; password must pass complexity check"""
    if request.method == 'POST':
        username = request.form['username'] #get username
        password = request.form['password'] #get password
        if check_duplicate(username, password) is True: #if UN exists in DB, take user to login page
            print("User is already registered. Sending to login.")
            return render_template('existing_user_login.html')
        elif check_complexity(password) is True and check_duplicate(username, password) is False:
            #if pw passes complexty & UN is new, register user
            user_data = f"{username}:{password}" #define as one var for writing to txt file
            write_to_file(user_data)
            return render_template('first_login.html')
        elif check_complexity(password) is False: #if password fails complexity test, re-render
            return render_template('register.html', error='Password must pass complexity test.')
    else:
        return render_template('register.html')

#series of checks to validate info needed to change password
@app.route('/verify_username', methods = ["GET", "POST"])
def verify_username():
    """registered user can change password"""
    if request.method == 'POST':
        username = request.form['username']
        old_pw = request.form['old_pw']
        new_pw = request.form['new_pw']
        new_pw_verify = request.form['new_pw_verify']

        if is_username_valid(username, filename) is True: #check that UN is stored
            if verify_user_info(username, old_pw) is True: #check that UN matches current password
                if do_pws_match(new_pw, new_pw_verify) is True: #check that NEW pws match
                    if is_pw_common(new_pw) is False: #check that new pw does not match common PWs
                        password = new_pw
                        if check_complexity(password) is True: #check that new pw passes complexity
                            usernames_pws(filename) #create list of previously stored users & PWs
                            update_password(username, new_pw, filename) #update pw to new version
                            print("password has been changed")
                        else: #else condition for failing complexity check
                            return render_template('verify_username.html')
                    else: #failed common password check
                        return render_template('verify_username.html')
                else: #failed matching new password check
                    return render_template('verify_username.html')
            else: #else condition for verifying user info
                return render_template('verify_username.html')
        else: #else conditions for checking if username is in database
            return render_template('verify_username.html')
    return render_template('verify_username.html')

def verify_user_info(username, old_pw):
    """Check if the inputted username is already registered"""
    user_data = read_file('users.txt')
    for data in user_data:
        entered_username, entered_password = data.split(':', 1) #split reg users into their UN & PW
        if username == entered_username and old_pw == entered_password: #check for info match
            return True
    return render_template('verify_username.html')

def do_pws_match(new_pw, new_pw_verify):
    """Verify that the new password is correctly inputted by user"""
    if new_pw == new_pw_verify:
        print(new_pw, new_pw_verify)
        return True
    return False

def is_pw_common(new_pw):
    """Verify that the new password does not match any in the common passwords doc"""
    bad_pws = read_file('CommonPassword.txt')
    for entry in bad_pws:
        if entry == new_pw: #if pw matches common pw, deny pw change
            return True
    return False

def reset_pw(username, old_pw, new_pw):
    """User changes their password from old to new"""
    password = old_pw
    if check_database(username, password) is True:
        old_pw = new_pw #rewrite password to new value after checks
        print(old_pw)

def get_usernames(user_data):
    """Pull usernames only from user.txt file to validate inputted username is stored
    for purposes of changing a user password"""
    usernames = []
    with open(user_data, 'r') as file:
        for line in file:
            username, _ = line.strip().split(':') #split entry into username and pw separately
            usernames.append(username)
    print(usernames)
    return usernames

def is_username_valid(username, user_data):
    """Check that username is in users list for pw change"""
    usernames = get_usernames(user_data)
    return username in usernames

@app.route('/login', methods = ["GET", "POST"])
def login():
    """Prompt user to login after registering successfully"""
    global login_counter #counter must be accessible in every method
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_database(username, password):
            login_counter = 0 #reset upon successful login
            return render_template('index.html')
        login_counter +=1 # counter +1 every failed login
        ip_address = request.remote_addr
        log_failed_login(username, ip_address)
        return render_template('invalid_login.html', error='Invalid username or password.')

@app.route('/first_login', methods = ["GET", "POST"])
def first_login():
    """Prompt user to login after registering successfully"""
    global login_counter
    if request.method == 'POST': #check for post method, prompt for UN & PW from user
        username = request.form['username']
        password = request.form['password']
        if check_database(username, password):
            login_counter = 0
            return render_template('index.html')
        login_counter += 1
        ip_address = request.remote_addr
        log_failed_login(username, ip_address)
        return render_template('invalid_login.html', error='Invalid username or password.')

@app.route('/existing_user_login', methods = ["GET", "POST"])
def existing_user_login():
    """Prompt existing user to login after duplicate username is detected
    at registration"""
    global login_counter
    if request.method == 'POST': #check for post method, prompt for UN & PW from user
        username = request.form['username']
        password = request.form['password']
        if check_database(username, password):
            login_counter = 0
            return render_template('index.html')
        login_counter += 1
        ip_address = request.remote_addr
        log_failed_login(username, ip_address)
        return render_template('invalid_login.html', error='Invalid username or password.')

@app.route('/invalid_login', methods = ["GET", "POST"])
def invalid_login():
    """Re-prompt for login credentials after incorrect login info given from user"""
    global login_counter
    if request.method == 'POST': #check for post method, prompt for UN & PW from user
        username = request.form['username']
        password = request.form['password']

        if check_database(username, password):
            login_counter = 0
            return render_template('index.html')
        login_counter += 1
        ip_address = request.remote_addr
        log_failed_login(username, ip_address)
        return render_template('invalid_login.html', login_counter=login_counter)

def log_failed_login(username, ip_address):
    """record all failed login attempts in separate file"""
    now = datetime.now()
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S') #record moment of failed login
    with open(LOG_FILE, 'a') as log_file: #create file that records failed login details
        log_file.write(f"[{timestamp}] Failed login by {username} from {ip_address}\n")

@app.route('/index/', methods = ["GET", "POST"])
def index():
    """template for html file that displays main site page"""
    now = datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S") #formatting datetime
    return render_template('index.html', current_time=current_time)


def check_complexity(password):
    """validate that password meets complexity check
    must have capital letter, number, and special char"""
    if re.search(r"[A-Z]", password) and re.search(r"\d", password) and re.search(r"[?!@#$%^&*()]", password):
        return True #pw must have a capital, a number, and a special character
    return False

def check_duplicate(username, password):
    """Check if the attempted username is already registered"""
    user_data = read_file('users.txt')
    for data in user_data:
        entered_username, entered_password = data.split(':', 1)
        if username == entered_username: #checking for username that was already registered
            return True
    return False

def hash_pw(password): #hash pw for security
    """if pw passes complexity check, convert to hashed version for secure storage"""
    hashed_pw = sha256_crypt.hash(password)
    return hashed_pw

def write_to_file(user_data): #write submitted users to file
    """Write user data to file for storage"""
    with open('users.txt', 'a') as file:
        file.write(user_data + '\n')

def read_file(filename):
    """Clean up data after approval"""
    with open(filename, 'r') as file:
        lines = file.readlines()
        stripped_lines = [line.strip() for line in lines]
        return stripped_lines

def check_database(username, password): #check that UN & PW are correct and match with each other
    """verify that user login info matches info of user stored in database"""
    user_data = read_file('users.txt')
    for data in user_data:
        stored_username, stored_password = data.split(':', 1)
        if username == stored_username and password == stored_password:
            return True
    return False

def usernames_pws(filename):
    """create accessible version of usernames and passwords txt file"""
    usernames_passwords = []
    with open(filename, 'r') as file:
        for line in file:
            username, password  = line.strip().split(':')
            usernames_passwords.append((username, password))
    return usernames_passwords

def update_password(username, new_pw, filename):
    """locate correct entry and overwrite the password"""
    usernames_passwords = usernames_pws(filename)

    for i, (u, p) in enumerate(usernames_passwords): #iterate database to search for username matchj
        if u == username:
            usernames_passwords[i] = (u, new_pw) #update password only
            break

    with open(filename, 'w') as file:
        for u, p in usernames_passwords:
            file.write(f"{u}:{p}\n")
        return u, p

#declaring page for writing samples
@app.route('/opinions/')
def show_opinions():
    """template for personal opinions page within site"""
    return render_template('opinions.html')

#route for about me section
@app.route('/about_sam/')
def show_about():
    """template for small about sam section"""
    return render_template('about_sam.html')
