# from flask import Flask, render_template, request, session

# app = Flask(__name__)
# app.secret_key = "your-secret-key"

# @app.route("/")
# def index():
#     session["username"] = "testuser"
#     session["token"] = "abc123"
#     return render_template(
#         "behavior3.html",
#         login_hint=session["username"],
#         error_message=None,
#         action_url="/Complete",
#     )

# @app.route("/Complete", methods=["POST"])
# def complete():
#     txn = session.get("token")
#     print("Transaction token:", txn)
#     print("Form data:", request.form)
#     return render_template("goodnight.html")

# if __name__ == "__main__":
#     app.run(debug=True)









from flask import Flask, render_template, request, session

app = Flask(__name__)
app.secret_key = "your-secret-key"

@app.route("/")
def index():
    session["username"] = "testuser"
    session["token"] = "abc123"
    return render_template(
        "behavior3.html",
        login_hint=session["username"],
        error_message=None,
        action_url="/Complete",
    )

@app.route("/Complete", methods=["POST"])
def complete():
    txn = session.get("token")
    print("Transaction token:", txn)
    session["form_data"] = request.form.to_dict()
    return render_template("goodnight.html")

@app.route("/formData")
def form_data():
    data = session.get("form_data", {})
    return render_template("formdata.html", form_data=data)

if __name__ == "__main__":
    app.run(debug=True)




















