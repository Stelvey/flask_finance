import os
from time import time
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, date

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd
app.jinja_env.filters["date"] = date

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT symbol, sum(shares) FROM history WHERE user_id = ? GROUP BY symbol", session["user_id"])

    total = 0
    for stock in stocks:
        stock["price"] = lookup(stock["symbol"])["price"]
        stock["value"] = stock["price"] * stock["sum(shares)"]
        total += stock["value"]

    balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    grand = balance + total

    return render_template("index.html", stocks=stocks, balance=balance, grand=grand)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if request.form.get("buy"):
            symbol = request.form.get("buy")
            return render_template("buy.html", symbol=symbol)

        if not request.form.get("symbol") or not lookup(request.form.get("symbol")):
            return apology("must provide valid symbol", 400)
        elif re.search("[^\d]", request.form.get("shares")):
            return apology("must provide valid shares", 400)
        elif not request.form.get("shares") or int(request.form.get("shares")) < 1:
            return apology("must buy at least 1 share", 400)
        else:
            balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
            price = lookup(request.form.get("symbol"))["price"]
            shares = int(request.form.get("shares"))
            total = shares * price

            if balance >= total:
                balance = balance - total
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])
                db.execute("INSERT INTO history (user_id, type, symbol, price, shares, timestamp) VALUES (?, 'Purchase', ?, ?, ?, ?)",
                           session["user_id"], request.form.get("symbol"), price, shares, int(time()))

                flash('Purchased successfully')
                return redirect("/")
            else:
                return apology("insufficient balance", 403)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute(
        "SELECT symbol, type, price, shares, timestamp FROM history WHERE user_id = ? ORDER BY id DESC", session["user_id"])
    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash('You were successfully logged in')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash('You were successfully logged out')
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if lookup(request.form.get("symbol")):
            return render_template("quoted.html", symbol=request.form.get("symbol"), price=lookup(request.form.get("symbol"))["price"])
        else:
            return apology("must provide valid symbol", 400)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        p = request.form.get("password")

        # Ensure username was submitted correctly
        if not request.form.get("username") or " " in request.form.get("username"):
            return apology("must provide a single word username", 400)

        elif db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username")):
            return apology("must provide a unique username", 400)

        # Ensure password was submitted correctly

        elif not p or " " in p:
            return apology("must provide a single word password", 400)

        elif len(p) < 8:
            return apology("password must be 8+ characters long", 400)

        elif not re.search("\W", p) or not re.search("[A-Z]", p) or not re.search("[a-z]", p) or not re.search("\d", p):
            return apology("password must contain: uppercase, lowercase, number, special character")

        # Ensure passwords match
        elif p != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        # Add a user to database
        new_id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                            request.form.get("username"), generate_password_hash(p))

        # Remember which user has logged in
        session["user_id"] = new_id

        # Redirect user to home page
        flash('You were successfully registered!')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        p = request.form.get("password")

        # Ensure password was submitted correctly

        if not p or " " in p:
            return apology("must provide a single word password", 403)

        elif len(p) < 8:
            return apology("password must be 8+ characters long", 403)

        elif not re.search("\W", p) or not re.search("[A-Z]", p) or not re.search("[a-z]", p) or not re.search("\d", p):
            return apology("password must contain: uppercase, lowercase, number, special character")

        # Ensure passwords match
        elif p != request.form.get("confirmation"):
            return apology("passwords must match", 403)

        # Push changed password to database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(p), session["user_id"])

        # Redirect user to home page
        flash('Your password has been changed')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("password.html")


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    """Add cash"""
    if request.method == "POST":
        c = request.form.get("cash")
        if not re.match("\d+[.\d]?\d*$", c) or float(c) <= 0:
            return apology("must provide valid amount", 403)
        else:
            balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"] + float(c)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])

            flash('Balance updated successfully')
            return redirect("/")
    else:
        return render_template("cash.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if request.form.get("sell"):
            symbol = request.form.get("sell")
            stocks = db.execute("SELECT symbol FROM history WHERE user_id = ? GROUP BY symbol", session["user_id"])
            return render_template("sell.html", symbol=symbol, stocks=stocks)

        if not request.form.get("symbol") or not lookup(request.form.get("symbol")):
            return apology("must provide valid symbol", 400)
        elif re.search("[^\d]", request.form.get("shares")):
            return apology("must provide valid shares", 400)
        elif not request.form.get("shares") or int(request.form.get("shares")) < 1:
            return apology("must sell at least 1 share", 400)
        else:
            balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
            owned = db.execute("SELECT sum(shares) FROM history WHERE user_id = ? AND symbol = ?",
                               session["user_id"], request.form.get("symbol"))[0]["sum(shares)"]
            price = lookup(request.form.get("symbol"))["price"]
            shares = -abs(int(request.form.get("shares")))
            total = shares * price

            if owned >= abs(shares):
                balance = balance - total
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])
                db.execute("INSERT INTO history (user_id, type, symbol, price, shares, timestamp) VALUES (?, 'Sell', ?, ?, ?, ?)",
                           session["user_id"], request.form.get("symbol"), price, shares, int(time()))

                flash('Sold succesfully')
                return redirect("/")
            else:
                return apology("insufficient shares", 400)
    else:
        stocks = db.execute("SELECT symbol FROM history WHERE user_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell.html", stocks=stocks)
