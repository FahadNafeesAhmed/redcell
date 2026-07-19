from flask import Flask, request

from app.service import handle

app = Flask(__name__)


@app.route("/chat", methods=["POST"])
def chat():
    msg = request.json["message"]   # SOURCE (untrusted)
    return handle(msg)              # flows cross-file -> LLM sink


@app.route("/user")
def user():
    uid = request.args["id"]        # SOURCE
    import sqlite3
    con = sqlite3.connect("x.db")
    return con.execute("SELECT * FROM u WHERE id=" + uid)  # SINK (same-file SQLi)
