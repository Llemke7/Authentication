from flask import Flask, redirect, url_for, render_template, session, flash, request
from models import db, User, Registration, Login, Feedback
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db.init_app(app)
bcrypt = Bcrypt(app)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registration()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password,
                    email=form.email.data, first_name=form.first_name.data,
                    last_name=form.last_name.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            return redirect(url_for('secret'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/secret')
def secret():
    if 'username' in session:
        username = session['username']  
        return render_template('secret.html', username=username) 
    else:
        flash('You must be logged in', 'warning')
        return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/users/<username>')
def user_profile(username):
    if 'username' in session and session['username'] == username:
        user = User.query.filter_by(username=username).first()
        if user:
            feedback = Feedback.query.filter_by(username=username).all()
            return render_template('user_profile.html', user=user, feedback=feedback)
    flash('You are not authorized to access this page.', 'danger')
    return redirect(url_for('login'))


@app.route('/add_feedback', methods=['GET', 'POST'])
def add_feedback():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        username = session['username']
        feedback = Feedback(title=title, content=content, username=username)
        db.session.add(feedback)
        db.session.commit()
        flash('Feedback added successfully', 'success')
        return redirect(url_for('user_profile', username=username))
    return render_template('add_feedback.html')

@app.route('/edit_feedback/<feedback_id>', methods=['GET', 'POST'])
def edit_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if feedback.username == session['username']:
        if request.method == 'POST':
            feedback.title = request.form['title']
            feedback.content = request.form['content']
            db.session.commit()
            flash('Feedback updated successfully', 'success')
            return redirect(url_for('user_profile', username=session['username']))
        return render_template('edit_feedback.html', feedback=feedback)
    flash('You are not authorized to edit this feedback', 'danger')
    return redirect(url_for('user_profile', username=session['username']))

@app.route('/delete_feedback/<feedback_id>', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if feedback.username == session['username']:
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback deleted successfully', 'success')
    else:
        flash('You are not authorized to delete this feedback', 'danger')
    return redirect(url_for('user_profile', username=session['username']))

@app.route('/delete_user', methods=['POST'])
def delete_user():
    username = session['username']
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('Your account has been deleted', 'success')
        session.clear()
    else:
        flash('User not found', 'danger')
    return redirect(url_for('home'))

@app.route('/user_feedback/<username>')
def user_feedback(username):
    if 'username' in session and session['username'] == username:
        user = User.query.filter_by(username=username).first()
        if user:
            feedback = Feedback.query.filter_by(username=username).all()
            return render_template('user_feedback.html', user=user, feedback=feedback)
    flash('You are not authorized to access this page.', 'danger')
    return redirect(url_for('login'))

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    if 'username' in session and session['username'] == username:
        user = User.query.filter_by(username=username).first()
        if user:
            Feedback.query.filter_by(username=username).delete()
            db.session.delete(user)
            db.session.commit()
            session.clear()
            flash('Your account has been deleted', 'success')
        else:
            flash('User not found', 'danger')
    else:
        flash('You are not authorized to delete this account', 'danger')
    return redirect(url_for('home'))



if __name__ == '__main__':
    app.run(debug=True)


