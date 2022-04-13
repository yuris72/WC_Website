from flask import Flask, render_template, request, session, redirect
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DB_NAME = "C:\\Users\\MassiveImpact72\\PycharmProjects\\web-app-yuris\\database.db"

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "702au98273has68fh9a83kj5y"


def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)

    return None


def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        connection.execute('pragma foreign_keys=ON')
        return connection
    except Error as e:
        print(e)

    return None


@app.route('/', methods=['GET', 'POST'])
def render_page_1():
    if is_logged_in():
        return redirect('/logged-in')

    if 'password2' in request.form:
        if request.method == 'POST':
            print(request.form)
            fname = request.form.get('fname').strip().title()
            lname = request.form.get('lname').strip().title()
            email = request.form.get('email').strip().lower()
            password = request.form.get('password')
            password2 = request.form.get('password2')

            if password != password2:
                return redirect('/?error=Passwords+Do+Not+Match')

            if len(password) < 8:
                return redirect('/?error=Password+Must+Be+8+Characters+Or+More')

            hashed_password = bcrypt.generate_password_hash(password)

            con = create_connection(DB_NAME)

            query = "INSERT INTO user(id, fname, lname, email, password) " \
                    "VALUES(NULL,?,?,?,?)"

            cur = con.cursor()
            try:
                cur.execute(query, (fname, lname, email, hashed_password))
            except sqlite3.IntegrityError:
                return redirect('/?error=Email+Is+Already+In+Use')

            con.commit()
            con.close()

        return render_template('home.html', logged_in=is_logged_in())
    else:
        if request.method == "POST":
            email = request.form['email'].strip().lower()
            password = request.form['password'].strip()

            query = """SELECT id, fname, lname, password FROM user WHERE email = ?"""
            con = create_connection(DB_NAME)
            cur = con.cursor()
            cur.execute(query, (email,))
            user_data = cur.fetchall()
            con.close()

            try:
                userid = user_data[0][0]
                firstname = user_data[0][1]
                lastname = user_data[0][2]
                db_password = user_data[0][3]
            except IndexError:
                return redirect("/?error=Email+Invalid+Or+Password+Incorrect")

            if not bcrypt.check_password_hash(db_password, password):
                return redirect("/?error=Email+Invalid+Or+Password+Incorrect")

            session['email'] = email
            session['userid'] = userid
            session['firstname'] = firstname
            session['lastname'] = lastname
            print(session)
            return redirect('/logged-in')

        return render_template('home.html', logged_in=is_logged_in())


@app.route('/logged-in', methods=['GET', 'POST'])
def render_page_2():
    if request.method == 'POST':
        print(request.form)
        rating = request.form.get('rating')
        print(rating)
        review = request.form.get('review')
        name = session['firstname'] + ' ' + session['lastname']

        if rating is None or len(review) == 0:
            return redirect('/logged-in?error=Rating+Or+Review+Not+Given')

        if len(review) > 500:
            return redirect('/logged-in?error=Review+Over+500+Characters')

        con = create_connection(DB_NAME)

        query = "INSERT INTO review(id, name, rating, review) " \
                "VALUES(NULL,?,?,?)"

        cur = con.cursor()

        try:
            cur.execute(query, (name, rating, review))
        except sqlite3.IntegrityError as e:
            print(e)
            print("### PROBLEM INSERTING INTO DATABASE - FOREIGN KEY ###")
            con.close()
            return redirect('/logged-in?error=Something+Went+Wrong')

        con.commit()
        con.close()
        return redirect('/logged-in')

    con = create_connection(DB_NAME)

    query = "SELECT name, rating, review, id " \
            "FROM review"

    cur = con.cursor()
    cur.execute(query)
    review_list = cur.fetchall()
    con.close()

    full_name = session['firstname'] + ' ' + session['lastname']
    print(full_name)

    return render_template('logged-in.html', reviews=review_list, full_name=full_name, logged_in=is_logged_in())


@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=See+You+Next+Time!')


@app.route('/remove/<full_name>')
def remove_review(full_name):
    print(full_name)
    query = """DELETE FROM review WHERE (name) = (?);"""
    con = create_connection(DB_NAME)
    cur = con.cursor()
    cur.execute(query, (full_name,))
    con.commit()
    con.close()
    return redirect('/logged-in')


def is_logged_in():
    if session.get("email") is None:
        print("not logged in")
        return False
    else:
        print("logged in")
        return True


app.run(host='0.0.0.0', debug=True)
