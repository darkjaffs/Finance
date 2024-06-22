import os

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
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

    id = session["user_id"]

    # get user data
    portfolio = db.execute(
        "SELECT stock, shares FROM userdata where id = ? GROUP BY stock HAVING shares",
        id,
    )

    current_cash = db.execute("SELECT cash FROM users where id = ?", id)
    current_cash = current_cash[0]["cash"]

    total_cash = 0
    final_cash = current_cash

    # loops over each stock
    for stock in portfolio:
        quote = lookup(stock["stock"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["value"] = stock["price"] * stock["shares"]
        total_cash = total_cash + stock["value"]
        final_cash = final_cash + stock["value"]

    total_cash = final_cash - total_cash

    # pass on the necessary stuff into template
    return render_template(
        "index.html",
        portfolio=portfolio,
        current_cash=current_cash,
        total_cash=float(total_cash),
        final_cash=float(final_cash),
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        id = session["user_id"]
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        # checking for validity
        if not symbol:
            return apology("invalid symbol")
        elif not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("enter correct shares")

        stockData = lookup(symbol)

        if stockData is None:
            return apology("symbol does not exist")

        stock_price = stockData["price"]
        user_cost = stock_price * int(shares)

        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", id)
        user_cash = user_cash[0]["cash"]

        if user_cost > user_cash:
            return apology("not enough cash")

        # verifying data
        verify = db.execute(
            "SELECT stock FROM userdata WHERE id = ? and stock = ?", id, symbol
        )

        if len(verify) > 0:
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?", (user_cash - user_cost), id
            )

            db.execute(
                "UPDATE userdata SET shares = shares + ? WHERE id = ? and stock = ?",
                shares,
                id,
                symbol,
            )

            db.execute(
                "INSERT INTO history (id,stock,shares,price, time) VALUES (?,?,?,?,?)",
                id,
                symbol,
                shares,
                stock_price,
                formatted_datetime,
            )

            return redirect("/")

        # inserting data
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", (user_cash - user_cost), id
        )

        db.execute(
            "INSERT INTO userdata (id, stock, shares, price) VALUES (?,?,?,?)",
            id,
            symbol,
            shares,
            stock_price,
        )

        db.execute(
            "INSERT INTO history (id,stock,shares,price, time) VALUES (?,?,?,?,?)",
            id,
            symbol,
            shares,
            stock_price,
            formatted_datetime,
        )

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    id = session["user_id"]
    history = db.execute("SELECT * FROM history WHERE id = ?", id)

    return render_template("history.html", history=history)


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
        result = lookup(symbol)

        if result is None:
            return apology("symbol does not exist", 400)

        return render_template("quoted.html", result=result)


@app.route("/register", methods=["GET", "POST"])
def register():
    """REGIISTER USER"""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmpass = request.form.get("confirmation")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif password != confirmpass:
            return apology("password must match", 400)

        verify = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(verify) > 0:
            return apology("username already exits", 400)

        hash = generate_password_hash(password, method="pbkdf2", salt_length=16)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        id = session["user_id"]
        portfolio = db.execute("SELECT * FROM userdata WHERE id = ?", id)

        return render_template("sell.html", portfolio=portfolio)

    elif request.method == "POST":
        # Selling
        id = session["user_id"]
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

        stocks = db.execute(
            "SELECT stock, shares FROM userdata WHERE id = ? GROUP BY stock HAVING shares > 0",
            id,
        )

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("enter symbol")
        elif not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("invlid shares")

        shares = int(shares)

        # loops over each stock
        for stock in stocks:
            if stock["stock"] == symbol:
                if stock["shares"] < shares:
                    return apology("share exceed the owned amount")
                else:
                    stockquote = lookup(symbol)
                    if stockquote is None:
                        return apology("symbol not found")

                    stock_price = stockquote["price"]
                    amount_sold = shares * stock_price

                    # enter data into table
                    db.execute(
                        "UPDATE users SET cash = cash + ? WHERE id = ?", amount_sold, id
                    )

                    if (stock["shares"] - shares) == 0:
                        db.execute(
                            "DELETE FROM userdata WHERE id = ? and stock = ?",
                            id,
                            symbol,
                        )

                    db.execute(
                        "UPDATE userdata SET shares = ? - shares WHERE id = ? and stock = ?",
                        shares,
                        id,
                        symbol,
                    )

                    db.execute(
                        "INSERT INTO history (id,stock,shares,price, time) VALUES (?,?,?,?,?)",
                        id,
                        stockquote["symbol"],
                        -shares,
                        stock_price,
                        formatted_datetime,
                    )
                    return redirect("/")

    # apology incase program doesnt run
    return apology("symbol not found")



