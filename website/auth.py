from flask import Blueprint, render_template, request, flash, redirect, url_for

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if ("admin" == password) & (username == "admin"):
                return redirect(url_for('views.home'))
        else:
            flash('Incorrect password, try again.', category='error')

    return render_template("login.html")