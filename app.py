from flask import Flask, render_template, redirect, url_for, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hireflow-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

ALLOWED_EXTENSIONS = {'pdf'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------- MODELS ----------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    company = db.Column(db.String(100))
    description = db.Column(db.Text)


class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    job_id = db.Column(db.Integer)

    email = db.Column(db.String(120))
    resume_file = db.Column(db.String(200))

    status = db.Column(db.String(50), default="Applied")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- HELPERS ----------------

def admin_required(func):
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            return "Access Denied", 403
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------- ROUTES ----------------

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db.session.add(User(
            username=request.form['username'],
            password=generate_password_hash(request.form['password']),
            role="user"
        ))
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        role = request.form['role']

        if user and check_password_hash(user.password, request.form['password']):
            if user.role != role:
                return "Invalid role selected", 403

            login_user(user)
            return redirect(url_for('admin_dashboard' if role == "admin" else 'jobs'))

    return render_template('login.html')


@app.route('/jobs')
@login_required
def jobs():
    jobs = Job.query.all()
    applied_jobs = [a.job_id for a in Application.query.filter_by(user_id=current_user.id)]
    return render_template('jobs.html', jobs=jobs, applied_jobs=applied_jobs)


# 🔥 APPLY WITH EMAIL + RESUME
@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required
def apply(job_id):
    job = Job.query.get(job_id)

    if request.method == 'POST':
        email = request.form['email']
        file = request.files['resume']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            db.session.add(Application(
                user_id=current_user.id,
                job_id=job_id,
                email=email,
                resume_file=filename
            ))
            db.session.commit()

            return redirect(url_for('my_applications'))

    return render_template('resume.html', job=job)


@app.route('/withdraw/<int:job_id>')
@login_required
def withdraw(job_id):
    application = Application.query.filter_by(
        user_id=current_user.id, job_id=job_id
    ).first()
    if application:
        db.session.delete(application)
        db.session.commit()
    return redirect(url_for('my_applications'))


@app.route('/applications')
@login_required
def my_applications():
    applications = db.session.query(Application, Job).join(
        Job, Application.job_id == Job.id
    ).filter(Application.user_id == current_user.id).all()
    return render_template('apply.html', applications=applications)


# ---------------- ADMIN ----------------

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    applications = db.session.query(
        Application, User, Job
    ).join(User, Application.user_id == User.id)\
     .join(Job, Application.job_id == Job.id).all()
    return render_template('admin.html', applications=applications)


@app.route('/resume/<filename>')
@login_required
@admin_required
def view_resume(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/update_status/<int:app_id>/<status>')
@login_required
@admin_required
def update_status(app_id, status):
    app_entry = Application.query.get(app_id)
    app_entry.status = status
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ---------------- INIT ----------------

with app.app_context():
    db.create_all()

    if not User.query.filter_by(username="admin").first():
        db.session.add(User(
            username="admin",
            password=generate_password_hash("admin123"),
            role="admin"
        ))
        db.session.commit()

    if not Job.query.first():
        db.session.add_all([
            Job(title="Software Engineer", company="TechCorp", description="Python & Flask Developer"),
            Job(title="Frontend Developer", company="UIWorks", description="HTML, CSS, JavaScript"),
            Job(title="Cyber Analyst", company="SecureX", description="SOC & Security Monitoring")
        ])
        db.session.commit()


if __name__ == "__main__":
    app.run()
