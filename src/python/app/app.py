import json
from flask import Flask, render_template, g, request, redirect, url_for, make_response, session, flash
from password_strength import PasswordPolicy
from html import escape
from hashlib import sha256
import logging, psycopg2
import binascii
import os
import pyotp
import uuid
import subprocess

policy = PasswordPolicy.from_names(
    length=8,    # Minimum length: 8
    uppercase=1, # Requires at least 1 uppercase letters
    numbers=1,   # Requires at least 1 digits
    special=1,   # Requires at least 1 special characters
)

app = Flask(__name__)
app.secret_key = "secret key"
COOKIE_TIMEOUT = 60 * 10





##########################################################
## INDEX
##########################################################

@app.route("/")
def home():

    return render_template("index.html");





##########################################################
## REGISTER
##########################################################

@app.route("/register_vuln", methods=['GET'])
def register_vulnerable():
    if 'username' in session or 'username' in request.cookies:
        return f'You cannot register because you are already logged in!<br><a href="/logout">Logout</a>'

    string = sha256(('cdss').encode('utf-8')).hexdigest()
    if string not in session and string not in request.cookies:
        return render_template("register_vuln.html")

    # Retrieve username and password
    if string in session:
        username = session[string].split('/')[0]
        password = session[string].split('/')[1]
    elif string in request.cookies:
        username = request.cookies.get(string).split('/')[0]
        password = request.cookies.get(string).split('/')[1]

    # Check if credentials check out
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT password FROM users WHERE username=%s", (username,))
    row = cur.fetchall()

    if row[0][0] == password:
        return f'You cannot register because you are already logged in!<br><a href="/logout">Logout</a>'
    else:
        # Remove cookie and session and redirect to the same page
        response = redirect('/register_vuln')
        if string in session:
            session.pop(string, None)
        if string in request.cookies:
            response.set_cookie(string, '', max_age=0)

        return response


@app.route("/register_vuln.html", methods=['GET', 'POST'])
def register_vulnerable_form():
    logger.info("---- register_vulnerable ----")

    # Retrieve login info
    password = request.args.get('v_password') 
    username = request.args.get('v_username')

    # Create SQL query (SQL INJECTABLE)
    query = f"SELECT username FROM users WHERE username='{username}'"

    # Check for common passwords (OS INJECTABLE)
    cmd = "grep %s pass.txt" % password
    result = subprocess.run(cmd, shell=True, capture_output=True)

    if result.returncode == 0:
        flash("Password is too weak!", "danger")
        return render_template("register_vuln.html")

    # Connect to database and retrieve user
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query)
    user_check = cur.fetchone()

    # If not already registered, enter user information into database
    if user_check is not None:
        flash("Username already exists in the database!")
        return render_template("register_vuln.html")
    else:
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
        cur.execute(query)
        conn.commit()
    
    return render_template("index.html")


@app.route("/register_correct", methods=['GET'])
def register_correct():
    if 'username' in session or 'username' in request.cookies:
        return f'You cannot register because you are already logged in!<br><a href="/logout">Logout</a>'

    string = sha256(('cdss').encode('utf-8')).hexdigest()
    if string not in session and string not in request.cookies:
        return render_template("register_correct.html")

    # Retrieve username and password
    if string in session:
        username = session[string].split('/')[0]
        password = session[string].split('/')[1]
    elif string in request.cookies:
        username = request.cookies.get(string).split('/')[0]
        password = request.cookies.get(string).split('/')[1]

    # Check if credentials check out
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT password FROM users WHERE username=%s", (username,))
    row = cur.fetchall()

    if row[0][0] == password:
        return f'You cannot register because you are already logged in!<br><a href="/logout">Logout</a>'
    else:
        # Remove cookie and session and redirect to the same page
        response = redirect('/register_correct')
        if string in session:
            session.pop(string, None)
        if string in request.cookies:
            response.set_cookie(string, '', max_age=0)

        return response


@app.route("/register_correct.html", methods=['POST'])
def register_correct_form():
    logger.info("---- register_correct ----")

    # Retrieve login info
    password = escape(request.form.get('c_password')) 
    confirm_password = escape(request.form.get('c_confirm_password'))
    username = escape(request.form.get('c_username'))

    if password != confirm_password:
        flash("Passwords don't match", "danger")
        return redirect(url_for("register_correct"))
    if len(policy.test(password)) != 0:
        flash("Password is not secure enough", "danger")
        return redirect(url_for("register_correct"))

    salt = binascii.hexlify(os.urandom(16)).decode('utf-8')
    hashed_password = sha256((password + salt).encode('utf-8')).hexdigest()

    # Connect to database and retrieve user
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT username FROM users WHERE username=%s", (username,))
    user_check = cur.fetchone()

    # If not already registered, enter user information into database
    if user_check is not None:
        flash("Username already exists in the database!", "danger")
        return redirect(url_for("register_correct"))
    else:
        # Generating random token for 2FA
        token = str(uuid.uuid4())
        cur.execute(f"INSERT INTO users (username, password, token, salt) VALUES (%s, %s, %s, %s)", (username, hashed_password, token, salt))
        conn.commit()
    
    return redirect(url_for("register_2fa", username=username, token=token))


# 2FA page route
@app.route("/register/2fa/<username>/<token>")
def register_2fa(username, token):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT username, token, secret FROM users WHERE username=%s", (username,))
    fetched_token = cur.fetchone()

    # Checking if token is valid and user associated
    if fetched_token[1] == token and fetched_token[2] is None:
        # generating random secret key for authentication
        secret = pyotp.random_base32()
        return render_template("register_2fa.html", secret=secret)
    else:
        return redirect(url_for("home"))


# 2FA form route
@app.route("/register/2fa/<username>/<token>", methods=["POST"])
def register_2fa_form(username, token):
    # getting secret key used by user
    secret = request.form.get("secret")
    # getting OTP provided by user
    otp = int(request.form.get("otp"))

    # verifying submitted OTP with PyOTP
    if pyotp.TOTP(secret).verify(otp):
        # inform users if OTP is valid
        flash("The 2FA token is valid", "success")
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"UPDATE users SET secret = %s WHERE username = %s", (secret, username))
        conn.commit()
        return redirect(url_for("home"))
    else:
        # inform users if OTP is invalid
        flash("The 2FA token is invalid! Please try again!", "danger")
        return redirect(request.referrer)





##########################################################
## PART 1
##########################################################

@app.route("/part1_vuln", methods=['GET'])
def part1_vulnerable():
    # Check if there is a previous session
    if 'username' in session or 'username' in request.cookies:
        return f'You are already logged in!<br><a href="/logout">Logout</a>'

    string = sha256(('cdss').encode('utf-8')).hexdigest()
    if string not in session and string not in request.cookies:
        return render_template("part1_vuln.html")

    # Retrieve username and password
    if string in session:
        username = session[string].split('/')[0]
        password = session[string].split('/')[1]
    elif string in request.cookies:
        username = request.cookies.get(string).split('/')[0]
        password = request.cookies.get(string).split('/')[1]

    # Check if credentials check out
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT password FROM users WHERE username=%s", (username,))
    row = cur.fetchall()

    if row[0][0] == password:
        return f'You are already logged in!<br><a href="/logout">Logout</a>'
    else:
        # Remove cookie and session and redirect to the same page
        response = redirect('/part1_vuln')
        if string in session:
            session.pop(string, None)
        if string in request.cookies:
            response.set_cookie(string, '', max_age=0)

        return response
    
    


@app.route("/part1_vuln.html", methods=['GET', 'POST'])
def part1_vulnerable_form():
    logger.info("---- part1_vulnerable ----")

    if request.method == 'GET':
        # Retrieve login info
        password = request.args.get('v_password') 
        username = request.args.get('v_username') 
        remember = request.args.get('v_remember')

        # Create SQL query (SQL INJECTABLE)
        query = f"SELECT * FROM users WHERE username='{username}'"

        # Connect to database and retrieve rows
        conn = get_db()
        cur = conn.cursor()
        cur.execute(query)
        row = cur.fetchall()

        # Delete accounts that did not finish 2FA configuration
        cur.execute("SELECT secret, token FROM users")
        rows = cur.fetchall()
        for account in rows:
            if account[0] == None and account[1] != None:
                cur.execute(f"DELETE FROM users WHERE token=%s", (account[1], ))
                conn.commit()

        # Authentication check
        if row == []:
            flash("Username does not exist!", "danger")
            return render_template("part1_vuln.html")
        else:
            if row[0][1] != password and sha256((password + str(row[0][4])).encode('utf-8')).hexdigest() != row[0][1]:
                flash("User exists but password is incorrect!", "danger")
                return render_template("part1_vuln.html")

        # Check if 'Remember me' was checked
        if remember:
            response = make_response(render_template('index.html'))
            response.set_cookie('username', username, max_age=COOKIE_TIMEOUT)
            response.set_cookie('password', password, max_age=COOKIE_TIMEOUT) # VULNERABLE
            return response
        else:
            session['username'] = username

        return render_template("index.html")

    return "POST"


@app.route("/part1_correct", methods=['GET'])
def part1_correct():
    # Check if there is a previous session
    if 'username' in session or 'username' in request.cookies:
        return f'You are already logged in!<br><a href="/logout">Logout</a>'

    string = sha256(('cdss').encode('utf-8')).hexdigest()
    if string not in session and string not in request.cookies:
        return render_template("part1_correct.html")

    # Retrieve username and password
    if string in session:
        username = session[string].split('/')[0]
        password = session[string].split('/')[1]
    elif string in request.cookies:
        username = request.cookies.get(string).split('/')[0]
        password = request.cookies.get(string).split('/')[1]

    # Check if credentials check out
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT password FROM users WHERE username=%s", (username,))
    row = cur.fetchall()

    logger.info(password)
    if row[0][0] == password:
        return f'You are already logged in!<br><a href="/logout">Logout</a>'
    else:
        # Remove cookie and session and redirect to the same page
        response = redirect('/part1_correct')
        if string in session:
            session.pop(string, None)
        if string in request.cookies:
            response.set_cookie(string, '', max_age=0)

        return response


@app.route("/part1_correct.html", methods=['POST'])
def part1_correct_form():
    logger.info("---- part1_correct ----")
    # Retrieve login info
    password = escape(request.form.get('c_password'))
    username = escape(request.form.get('c_username'))
    code =  escape(request.form.get('c_2fa'))
    remember = request.form.get('c_remember')

    # Connect to database and retrieve rows
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username=%s", (username,))
    row = cur.fetchall()

    # Delete accounts that did not finish 2FA configuration
    cur.execute("SELECT secret, token FROM users")
    rows = cur.fetchall()
    for account in rows:
        if account[0] == None and account[1] != None:
            cur.execute(f"DELETE FROM users WHERE token=%s", (account[1], ))
            conn.commit()

    # Authentication check
    if row == []:
        flash("Authentication error!", "danger")
        return redirect(url_for("part1_correct"))
    else:
        if row[0][1] != password and sha256((password + row[0][4]).encode('utf-8')).hexdigest() != row[0][1]:
            flash("Authentication error!", "danger")
            return redirect(url_for("part1_correct"))

    # 2FA verification
    if pyotp.TOTP(row[0][2]).verify(code):
        # Inform users if OTP is valid
        flash("The TOTP 2FA token is valid", "success")
        # Check if 'Remember me' was checked
        if remember:
            response = make_response(redirect(url_for('home')))
            response.set_cookie(sha256(('cdss').encode('utf-8')).hexdigest(), username + '/' + sha256((password + row[0][4]).encode('utf-8')).hexdigest(), max_age=COOKIE_TIMEOUT)
            return response
        else:
            session[sha256(('cdss').encode('utf-8')).hexdigest()] = username + '/' + sha256((password + row[0][4]).encode('utf-8')).hexdigest()

        return redirect(url_for("home"))
    else:
        flash("The 2FA code is invalid", "danger")
        return redirect(url_for("part1_correct"))


@app.route('/logout')
def logout():
    response = redirect('/')

    if 'username' in session:
        session.pop('username', None)

    if sha256(('cdss').encode('utf-8')).hexdigest() in session:
        session.pop(sha256(('cdss').encode('utf-8')).hexdigest(), None)
    
    if 'username' in request.cookies:
        response.set_cookie('username', '', max_age=0)
        response.set_cookie('password', '', max_age=0)

    if sha256(('cdss').encode('utf-8')).hexdigest() in request.cookies:
        response.set_cookie(sha256(('cdss').encode('utf-8')).hexdigest(), '', max_age=0)

    return response





##########################################################
## PART 2
##########################################################

@app.route("/part2_vuln", methods=['GET'])
def part2_vulnerable():
    # Check if there is a previous session
    string = sha256(('cdss').encode('utf-8')).hexdigest()
    if 'username' not in session and 'username' not in request.cookies and string not in session and string not in request.cookies:
        return "You don't have permission to access this page!"

    if string in session or string in request.cookies:
        # Retrieve username and password
        if string in session:
            username = session[string].split('/')[0]
            password = session[string].split('/')[1]
        elif string in request.cookies:
            username = request.cookies.get(string).split('/')[0]
            password = request.cookies.get(string).split('/')[1]

        # Check if credentials check out
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT password FROM users WHERE username=%s", (username, ))
        row = cur.fetchall()

        if row[0][0] != password:
            # Remove cookie and session and redirect to the same page
            response = redirect('/part2_vuln')
            if string in session:
                session.pop(string, None)
            if string in request.cookies:
                response.set_cookie(string, '', max_age=0)

            return response

    # MAIN PAGE
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM messages")
    rows = cur.fetchall()
    return render_template("part2_vuln.html", variable=rows);
        

@app.route("/part2_vuln.html", methods=['GET', 'POST'])
def part2_vulnerable_form():
    logger.info("---- part2_vuln ----")
    # Get message from request
    message = request.args.get('v_text')

    # Create SQL query (SQL INJECTABLE)
    query = f"INSERT INTO messages (author, message) VALUES ('{request.cookies.get('username')}', '{message}')"

    # Connect to database and insert message
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query)
    conn.commit()

    # Retrieve messages from database
    query = f"SELECT * FROM messages"
    cur.execute(query)
    rows = cur.fetchall()

    return render_template("part2_vuln.html", variable=rows);


@app.route("/part2_correct", methods=['GET'])
def part2_correct():
    # Check if there is a previous session
    string = sha256(('cdss').encode('utf-8')).hexdigest()
    if 'username' not in session and 'username' not in request.cookies and string not in session and string not in request.cookies:
        return "You don't have permission to access this page!"

    if string in session or string in request.cookies:
        # Retrieve username and password
        if string in session:
            username = session[string].split('/')[0]
            password = session[string].split('/')[1]
        elif string in request.cookies:
            username = request.cookies.get(string).split('/')[0]
            password = request.cookies.get(string).split('/')[1]

        # Check if credentials check out
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT password FROM users WHERE username=%s", (username,))
        row = cur.fetchall()

        if row[0][0] != password:
            # Remove cookie and session and redirect to the same page
            response = redirect('/part2_correct')
            if string in session:
                session.pop(string, None)
            if string in request.cookies:
                response.set_cookie(string, '', max_age=0)

            return response

    # MAIN PAGE
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM messages")
    rows = cur.fetchall()
    return render_template("part2_correct.html", variable=rows);


@app.route("/part2_correct.html", methods=['GET', 'POST'])
def part2_correct_form():
    logger.info("---- part2_correct ----")
    # Get message from request
    message = request.args.get('c_text')
    message = escape(message)

    # Connect to database and insert message
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"INSERT INTO messages (author, message) VALUES (%s, %s)", (request.cookies.get('username'), message))
    conn.commit()

    # Retrieve messages from database
    cur.execute(f"SELECT * FROM messages")
    rows = cur.fetchall()

    return render_template("part2_correct.html", variable=rows);





##########################################################
## PART 3
##########################################################

@app.route("/part3_vuln", methods=['GET'])
def part3_vulnerable():
    # Check if there is a previous session
    string = sha256(('cdss').encode('utf-8')).hexdigest()
    if 'username' not in session and 'username' not in request.cookies and string not in session and string not in request.cookies:
        return "You don't have permission to access this page!"

    if string in session or string in request.cookies:
        # Retrieve username and password
        if string in session:
            username = session[string].split('/')[0]
            password = session[string].split('/')[1]
        elif string in request.cookies:
            username = request.cookies.get(string).split('/')[0]
            password = request.cookies.get(string).split('/')[1]

        # Check if credentials check out
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT password FROM users WHERE username=%s", (username,))
        row = cur.fetchall()

        if row[0][0] != password:
            # Remove cookie and session and redirect to the same page
            response = redirect('/part2_vuln')
            if string in session:
                session.pop(string, None)
            if string in request.cookies:
                response.set_cookie(string, '', max_age=0)

            return response

    # MAIN PAGE
    return render_template("part3_vuln.html", show_output=False);


@app.route("/part3_vuln.html", methods=['GET', 'POST'])
def part3_vulnerable_form():
    conn = get_db()
    cur = conn.cursor()

    # Retrieve the search parameters from the request
    title = request.args.get('v_name')
    authors = request.args.get('v_author')
    category = request.args.get('v_category')
    min_price = request.args.get('v_pricemin')
    max_price = request.args.get('v_pricemax')
    search_term = request.args.get('v_search_input')
    search_in = request.args.get('v_search_field')
    match_method = request.args.get('v_radio_match')
    date_type = request.args.get('v_sp_d')
    date_range = request.args.get('v_sp_date_range')
    min_date = f"{request.args.get('v_sp_start_year')}-{request.args.get('v_sp_start_month')}-{request.args.get('v_sp_start_day')}"
    max_date = f"{request.args.get('v_sp_end_year')}-{request.args.get('v_sp_end_month')}-{request.args.get('v_sp_end_day')}"
    limit = request.args.get('v_sp_c')
    show_desc = request.args.get('v_sp_m')
    order_by = request.args.get('v_sp_s')

    # Construct the WHERE clause for the SQL query based on the search parameters
    where_clauses = []
    if title:
        where_clauses.append(f"title ILIKE '{title}'")
    if authors:
        where_clauses.append(f"authors ILIKE '{authors}'")
    if category:
        where_clauses.append(f"category ILIKE '{category}'")
    if search_term:
        if search_in == 'title':
            where_clauses.append(f"title ILIKE '%{search_term}%'")
        elif search_in == 'authors':
            where_clauses.append(f"authors ILIKE '%{search_term}%'")
        elif search_in == 'desc':
            where_clauses.append(f"description ILIKE '%{search_term}%'")
        elif search_in == 'keys':
            where_clauses.append(f"keywords ILIKE '%{search_term}%'")
        elif search_in == 'notes':
            where_clauses.append(f"notes ILIKE '%{search_term}%'")
        else:
            if match_method == 'any' or match_method == 'all':
                words = search_term.split()
                clause = []
                for word in words:
                    clause.append(f"title ILIKE '%{word}%' OR authors ILIKE '%{word}%' OR description ILIKE '%{word}%' OR keywords ILIKE '%{word}%' OR notes ILIKE '%{word}%'")
                if match_method == 'any':
                    where_clauses.append(') OR ('.join(clause))
                else:
                    where_clauses.append(') AND ('.join(clause))
            elif match_method == 'phrase':
                where_clauses.append(f"title ILIKE '%{search_term}%' OR authors ILIKE '%{search_term}%' OR description ILIKE '%{search_term}%' OR keywords ILIKE '%{search_term}%' OR notes ILIKE '%{search_term}%'")
    if min_price:
        where_clauses.append(f"price >= {min_price}")
    if max_price:
        where_clauses.append(f"price <= {max_price}") 
    if date_type == 'custom':
        if date_range != '-1':
            where_clauses.append(f"book_date > (CURRENT_DATE - INTERVAL '{date_range} days')")
    else:
        if min_date != '-0-0':
            where_clauses.append(f"book_date >= '{min_date}'")
        if max_date != '-0-0':
            where_clauses.append(f"book_date <= '{max_date}'")

    # Construct the final WHERE clause by joining all the individual WHERE clauses with AND
    where_clause = ') AND ('.join(where_clauses)
    if where_clause:
        where_clause = 'WHERE (' + where_clause + ')'

    # Construct the final SQL query
    if show_desc == '1':
        sql = f"SELECT title, authors, category, price, description FROM books {where_clause}"
    else:
        sql = f"SELECT title, authors, category, price FROM books {where_clause}"
    if order_by == 'relevance':
        sql += ' ORDER BY recomendation DESC'
    else:
        sql += ' ORDER BY book_date DESC'
    sql += f' LIMIT {limit}'

    cur.execute(sql)

    # Fetch the search results
    rows = cur.fetchall()

    return render_template("part3_vuln.html", variable=rows, show_output=True, show_desc=show_desc);


@app.route("/part3_correct", methods=['GET'])
def part3_correct():
    # Check if there is a previous session
    string = sha256(('cdss').encode('utf-8')).hexdigest()
    if 'username' not in session and 'username' not in request.cookies and string not in session and string not in request.cookies:
        return "You don't have permission to access this page!"

    if string in session or string in request.cookies:
        # Retrieve username and password
        if string in session:
            username = session[string].split('/')[0]
            password = session[string].split('/')[1]
        elif string in request.cookies:
            username = request.cookies.get(string).split('/')[0]
            password = request.cookies.get(string).split('/')[1]

        # Check if credentials check out
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT password FROM users WHERE username=%s", (username,))
        row = cur.fetchall()

        if row[0][0] != password:
            # Remove cookie and session and redirect to the same page
            response = redirect('/part2_vuln')
            if string in session:
                session.pop(string, None)
            if string in request.cookies:
                response.set_cookie(string, '', max_age=0)

            return response

    # MAIN PAGE
    return render_template("part3_correct.html");


@app.route("/part3_correct.html", methods=['GET', 'POST'])
def part3_correct_form():
    conn = get_db()
    cur = conn.cursor()

    # Retrieve the search parameters from the request
    title = escape(request.args.get('c_name'))
    authors = escape(request.args.get('c_author'))
    category = escape(request.args.get('c_category'))
    min_price = escape(request.args.get('c_pricemin'))
    max_price = escape(request.args.get('c_pricemax'))
    search_term = escape(request.args.get('c_search_input'))
    search_in = escape(request.args.get('c_search_field'))
    match_method = escape(request.args.get('c_radio_match'))
    date_type = escape(request.args.get('c_sp_d'))
    date_range = escape(request.args.get('c_sp_date_range'))
    min_date = escape(f"{request.args.get('c_sp_start_year')}-{request.args.get('c_sp_start_month')}-{request.args.get('c_sp_start_day')}")
    max_date = escape(f"{request.args.get('c_sp_end_year')}-{request.args.get('c_sp_end_month')}-{request.args.get('c_sp_end_day')}")
    limit = escape(request.args.get('c_sp_c'))
    show_desc = escape(request.args.get('c_sp_m'))
    order_by = escape(request.args.get('c_sp_s'))

    # Construct the WHERE clause for the SQL query based on the search parameters
    where_clauses = []
    params = []
    if title:
        where_clauses.append(f"title ILIKE %s")
        params.append(title)
    if authors:
        where_clauses.append(f"authors ILIKE %s")
        params.append(authors)
    if category:
        where_clauses.append(f"category ILIKE %s")
        params.append(category)
    if search_term:
        if search_in == 'title':
            where_clauses.append(f"title ILIKE %s")
            params.append(search_term)
        elif search_in == 'authors':
            where_clauses.append(f"authors ILIKE %s")
            params.append(search_term)
        elif search_in == 'desc':
            where_clauses.append(f"description ILIKE %s")
            params.append(search_term)
        elif search_in == 'keys':
            where_clauses.append(f"keywords ILIKE %s")
            params.append(search_term)
        elif search_in == 'notes':
            where_clauses.append(f"notes ILIKE %s")
            params.append(search_term)
        else:
            if match_method == 'any' or match_method == 'all':
                words = search_term.split()
                clause = []
                for word in words:
                    clause.append(f"title ILIKE %s OR authors ILIKE %s OR description ILIKE %s OR keywords ILIKE %s OR notes ILIKE %s")
                    params += [f'%{word}%' for i in range(5)]
                if match_method == 'any':
                    where_clauses.append(') OR ('.join(clause))
                else:
                    where_clauses.append(') AND ('.join(clause))
            elif match_method == 'phrase':
                where_clauses.append(f"title ILIKE %s OR authors ILIKE %s OR description ILIKE %s OR keywords ILIKE %s OR notes ILIKE %s")
                params += [f'%{search_term}' for i in range(5)]
    if min_price and min_price.isnumeric():
        where_clauses.append(f"price >= %s")
        params.append(min_price)
    if max_price and max_price.isnumeric():
        where_clauses.append(f"price <= %s") 
        params.append(max_price)
    if date_type == 'custom':
        if date_range != -1 and date_range.isnumeric():
            where_clauses.append(f"book_date > (CURRENT_DATE - INTERVAL '{date_range} days')")
    elif request.args.get('c_sp_start_year').isnumeric() and request.args.get('c_sp_start_month').isnumeric() and request.args.get('c_sp_start_day').isnumeric() and\
         request.args.get('c_sp_end_year').isnumeric() and request.args.get('c_sp_end_month').isnumeric() and request.args.get('c_sp_end_day').isnumeric():
        if min_date != '-0-0':
            where_clauses.append(f"book_date >= %s")
            params.append(min_date)
        if max_date != '-0-0':
            where_clauses.append(f"book_date <= %s")
            params.append(max_date)

    # Construct the final WHERE clause by joining all the individual WHERE clauses with AND
    where_clause = ') AND ('.join(where_clauses)
    if where_clause:
        where_clause = 'WHERE (' + where_clause + ')'

    # Construct the final SQL query
    if show_desc == '1':
        sql = f"SELECT title, authors, category, price, description FROM books {where_clause}"
    else:
        sql = f"SELECT title, authors, category, price FROM books {where_clause}"
    if order_by == 'relevance':
        sql += ' ORDER BY recomendation DESC'
    else:
        sql += ' ORDER BY book_date DESC'
    sql += f' LIMIT %s'
    params.append(limit)

    cur.execute(sql, params)

    # Fetch the search results
    rows = cur.fetchall()

    return render_template("part3_correct.html", variable=rows, show_output=True, show_desc=show_desc);





##########################################################
## DATABASE ACCESS
##########################################################

def get_db():
    db = psycopg2.connect(user = "ddss-database-assignment-2",
                password = "ddss-database-assignment-2",
                host = "db",
                port = "5432",
                database = "ddss-database-assignment-2")
    return db





##########################################################
## MAIN
##########################################################

if __name__ == "__main__":
    logging.basicConfig(filename="logs/log_file.log")

    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # Create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s:  %(message)s')

    # Add formatter to ch
    ch.setFormatter(formatter)

    # Add ch to logger
    logger.addHandler(ch)

    logger.info("\n---------------------\n\n")

    app.run(host="0.0.0.0", threaded=True)
