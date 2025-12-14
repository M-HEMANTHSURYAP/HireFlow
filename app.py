from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hireflow-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------- MODELS ----------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    company = db.Column(db.String(100))
    description = db.Column(db.Text)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    job_id = db.Column(db.Integer)
    status = db.Column(db.String(50), default="Applied")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ----------------

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'])
        user = User(username=request.form['username'], password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('jobs'))
    return render_template('login.html')

@app.route('/jobs')
@login_required
def jobs():
    jobs = Job.query.all()
    applied_jobs = [
        app.job_id for app in Application.query.filter_by(user_id=current_user.id)
    ]
    return render_template('jobs.html', jobs=jobs, applied_jobs=applied_jobs)

@app.route('/apply/<int:job_id>')
@login_required
def apply(job_id):
    already_applied = Application.query.filter_by(
        user_id=current_user.id,
        job_id=job_id
    ).first()

    if not already_applied:
        application = Application(
            user_id=current_user.id,
            job_id=job_id
        )
        db.session.add(application)
        db.session.commit()

    return redirect(url_for('my_applications'))

@app.route('/applications')
@login_required
def my_applications():
    applications = db.session.query(Application, Job).join(
        Job, Application.job_id == Job.id
    ).filter(Application.user_id == current_user.id).all()

    return render_template('apply.html', applications=applications)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------- INIT ----------------

with app.app_context():
    db.create_all()
    if not Job.query.first():
        db.session.add_all([
            Job(title="Software Engineer", company="TechCorp", description="Python & Flask Developer"),
            Job(title="Frontend Developer", company="UIWorks", description="HTML, CSS, JavaScript"),
            Job(title="Cyber Analyst", company="SecureX", description="SOC & Security Monitoring")
        ])
        db.session.commit()

if __name__ == "__main__":
    app.run()

