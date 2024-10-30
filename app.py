import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    #get users stock and shares
    stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", session["user_id"])

    #get users cash balance
    cash = db.execute("SELECT cash FROM users WHERE id =?", session["user_id"])[0]["cash"]

    #Initialize variable for total values
    total_value = cash

    #Iterate over stocks and add price and total value
    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["symbol"] = quote["symbol"]
        stock["price"] = quote["price"]
        stock["value"] = stock["price"] * stock["total_shares"]
        total_value += stock["value"]

    return render_template("index.html", stocks=stocks, cash=usd(cash), total_value=usd(total_value))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    elif request.method == "POST":
        cash = db.execute("SELECT cash FROM users WHERE id =?", session["user_id"])[0]["cash"]
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("missing symbol", 400)
        elif not shares:
            return apology("missing share", 400)
        elif not shares.isdigit():
            return apology("share must be positive integer", 400)
        else:
            shares = int(shares)
        if shares <= 0:
            return apology("shares must be a positive integer", 400)
        stock_data = lookup(symbol)
        if not stock_data:
            return apology("invalid symbol", 400)
        total_cost = float(stock_data["price"]) * int(shares)
        if total_cost >= cash:
            return apology("can not afford", 400)
        else:
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, session["user_id"])
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session["user_id"], symbol, shares, stock_data["price"])
            flash(f"Bought {shares} of {symbol} for {usd(stock_data["price"])}")
            return redirect("/")


@app.route("/history", methods=["GET"])
@login_required
def history():
    """Show history of transactions"""
    if request.method == "GET":
        transactions = db.execute("SELECT symbol, shares, price, transacted FROM transactions WHERE user_id = ? ORDER BY transacted DESC", session["user_id"])
        return render_template("history.html", transactions=transactions)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
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
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    elif request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Symbol is required", 400)
        stock_data = lookup(symbol)
        if not stock_data:
            return apology("Invalid symbol", 400)
        else:
            return render_template("quoted.html", stock=stock_data)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    if request.method == "POST":
        if not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)
        elif password != confirmation:
            return apology("password don't match", 400)
        hashed_password = generate_password_hash(password)

        try:
            #Chèn người dùng vào cơ sở dữ liệu
            rows = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)
            user_id = user_id = db.execute("SELECT last_insert_rowid()")[0]["last_insert_rowid()"]
        except ValueError:
            return apology("username taken", 400)
        session["user_id"] = user_id
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", session["user_id"])
        return render_template("sell.html", stocks=stocks)
    elif request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if not symbol:
            return apology("symbol required", 400)
        elif not shares:
            return apology("share is missing", 400)
        else:
            stock_data = lookup(symbol)
            stocks = db.execute("SELECT SUM(shares) as total_shares FROM transactions WHERE symbol = ?", symbol)
            total_shares = stocks[0]["total_shares"]
            if total_shares < shares:
                return apology("not enough share", 400)
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",session["user_id"], symbol, -shares, stock_data["price"])
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", (shares * stock_data["price"]), session["user_id"])
            flash(f"Sold {shares} share of {symbol} at {usd(stock_data["price"])} each")
            return redirect("/")

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "GET":
        return render_template("deposit.html")
    elif request.method == "POST":
        money = request.form.get("money")
        if money:
            money = int(money)
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", money, session["user_id"])
        flash(f"Added {usd(money)} to your balance!")
        return redirect("/")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
