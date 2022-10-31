from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import UserForm, LoginForm, FeedbackForm
# from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///flask_feedback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def root():
    return redirect('/register')

@app.route('/register', methods=["GET", "POST"])
def register_user():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username, password, email, first_name, last_name)

        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect(f'/users/{username}')
    return render_template('register.html', form=form)

@app.route('/users/<username>', methods=['GET', 'POST'])
def secret(username):
    username = User.query.get_or_404(username)
    return render_template('secret.html', user=username)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['username'] = user.username
            return redirect(f'/users/{username}')
        else:
            form.username.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)

@app.route('/logout')
def logout_user():
    session.pop('username')
    flash("Goodbye!", "info")
    return redirect('/')

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def show_feedback(username):
    if "username" not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    form = FeedbackForm()
    feedback = Feedback.query.filter_by(username=username).all()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_feedback = Feedback(title=title, content=content, username=session['username'])
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback Created!', 'success')
        return redirect(f'/users/{username}')

    return render_template("feedback.html", form=form, feedback=feedback)

@app.route('/feedback/<id>/delete', methods=["POST"])
def delete_feedback(id):
    """Delete tweet"""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    feedback = Feedback.query.get_or_404(id)
    if feedback.username == session['username']:
        db.session.delete(feedback)
        db.session.commit()
        flash("Feedback deleted!", "info")
        return redirect(f'/users/{feedback.username}')
    flash("You don't have permission to do that!", "danger")
    return redirect(f'/users/{feedback.username}')

@app.route('/user/<username>/delete', methods=["POST"])
def delete_user(username):
    """Delete user"""
    if 'username' not in session:
        flash("Must login first!", "danger")
        return redirect('/login')
    user = User.query.get_or_404(username)
    if user.username == session['username']:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted!", "info")
        return redirect('/')
    flash("You don't have permission to do that!", "danger")
    return redirect(f'/users/{user.username}')

@app.route('/feedback/<id>/update', methods=["GET","POST"])
def update_feedback(id):
    """Update feedback"""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    feedback = Feedback.query.get_or_404(id)
    form = FeedbackForm()
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash('Feedback Updated!', 'success')
        return redirect(f'/users/{feedback.username}')
    return render_template('update.html', form=form, feedback=feedback)



