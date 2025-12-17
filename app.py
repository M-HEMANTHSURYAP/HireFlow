from flask import (
    Flask, render_template, redirect,
    url_for, request, send_from_directory, flash
)
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

# ================= MODELS =================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20))  # user | admin | company


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    company = db.Column(db.String(100))  # company username
    description = db.Column(db.Text)
    job_type = db.Column(db.String(20), default="platform")
    # values: platform | company


class JobRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_username = db.Column(db.String(100))
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    skills = db.Column(db.String(200))
    experience = db.Column(db.String(50))
    status = db.Column(db.String(50), default="Pending")


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

# ================= HELPERS =================

def admin_required(func):
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            return "Access Denied", 403
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


def company_required(func):
    def wrapper(*args, **kwargs):
        if current_user.role != "company":
            return "Access Denied", 403
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ================= AUTH =================

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
        flash("Successfully registered", "success")
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        role = request.form['role']

        if user and check_password_hash(user.password, request.form['password']):
            if user.role != role:
                flash("Invalid role selected", "danger")
                return redirect(url_for('login'))

            login_user(user)

            if role == "admin":
                return redirect(url_for('admin_dashboard'))
            if role == "company":
                return redirect(url_for('company_dashboard'))
            return redirect(url_for('jobs'))

        flash("Invalid credentials", "danger")
    return render_template('login.html')

# ================= USER =================

@app.route('/jobs')
@login_required
def jobs():
    company_jobs = Job.query.filter_by(job_type="company").all()
    platform_jobs = Job.query.filter_by(job_type="platform").all()

    applications = {
        a.job_id: a.status
        for a in Application.query.filter_by(user_id=current_user.id).all()
    }

    return render_template(
        'jobs.html',
        company_jobs=company_jobs,
        platform_jobs=platform_jobs,
        applications=applications
    )


@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required
def apply(job_id):
    job = Job.query.get_or_404(job_id)

    if request.method == 'POST':
        file = request.files['resume']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # prevent duplicate applications
            existing = Application.query.filter_by(
                user_id=current_user.id,
                job_id=job_id
            ).first()

            if not existing:
                db.session.add(Application(
                    user_id=current_user.id,
                    job_id=job_id,
                    email=request.form['email'],
                    resume_file=filename
                ))
                db.session.commit()

            flash("Applied successfully", "success")
            return redirect(url_for('jobs'))

        flash("Only PDF allowed", "danger")

    return render_template('resume.html', job=job)

# ================= COMPANY =================

@app.route('/company')
@login_required
@company_required
def company_dashboard():
    jobs = JobRequest.query.filter_by(
        company_username=current_user.username
    ).all()
    return render_template('company_dashboard.html', jobs=jobs)


@app.route('/company/add-job', methods=['GET', 'POST'])
@login_required
@company_required
def company_add_job():
    if request.method == 'POST':
        db.session.add(JobRequest(
            company_username=current_user.username,
            title=request.form['title'],
            description=request.form['description'],
            skills=request.form['skills'],
            experience=request.form['experience']
        ))
        db.session.commit()
        flash("Job sent for admin approval", "success")
        return redirect(url_for('company_dashboard'))

    return render_template('company_add_job.html')


@app.route('/company/shortlisted')
@login_required
@company_required
def company_shortlisted():
    jobs = Job.query.filter_by(company=current_user.username).all()
    job_ids = [job.id for job in jobs]

    applications = db.session.query(
        Application, User, Job
    ).join(User, Application.user_id == User.id)\
     .join(Job, Application.job_id == Job.id)\
     .filter(
        Application.job_id.in_(job_ids),
        Application.status == "Shortlisted"
     ).all()

    return render_template(
        "company_shortlisted.html",
        applications=applications
    )
@app.route('/company/applications')
@login_required
@company_required
def company_applications():
    # Get jobs posted by this company
    jobs = Job.query.filter_by(company=current_user.username).all()
    job_ids = [job.id for job in jobs]

    # Get applications only for those jobs
    applications = db.session.query(
        Application, User, Job
    ).join(User, Application.user_id == User.id) \
     .join(Job, Application.job_id == Job.id) \
     .filter(Application.job_id.in_(job_ids)) \
     .all()

    return render_template(
        'company_applications.html',
        applications=applications
    )

# ================= ADMIN =================

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    applications = db.session.query(
        Application, User, Job
    ).join(User, Application.user_id == User.id)\
     .join(Job, Application.job_id == Job.id)\
     .filter(Application.status == "Applied")\
     .all()

    return render_template('admin.html', applications=applications)


# ✅ FIXED: ADMIN HISTORY ROUTE
@app.route('/admin/history')
@login_required
@admin_required
def admin_history():
    applications = db.session.query(
        Application, User, Job
    ).join(User, Application.user_id == User.id)\
     .join(Job, Application.job_id == Job.id)\
     .filter(Application.status != "Applied")\
     .all()

    return render_template(
        'admin_history.html',
        applications=applications
    )


@app.route('/admin/job-requests')
@login_required
@admin_required
def admin_job_requests():
    jobs = JobRequest.query.filter_by(status="Pending").all()
    return render_template('admin_job_requests.html', jobs=jobs)


@app.route('/admin/job-action/<int:job_id>/<action>')
@login_required
@admin_required
def admin_job_action(job_id, action):
    job_req = JobRequest.query.get_or_404(job_id)

    if action == "approve":
        db.session.add(Job(
            title=job_req.title,
            company=job_req.company_username,
            description=job_req.description,
            job_type="company"
        ))

        job_req.status = "Approved"

    elif action == "reject":
        job_req.status = "Rejected"

    db.session.commit()
    flash("Job action completed", "success")
    return redirect(url_for('admin_job_requests'))


@app.route('/update_status/<int:app_id>/<status>')
@login_required
@admin_required
def update_status(app_id, status):
    application = Application.query.get_or_404(app_id)
    application.status = status
    db.session.commit()
    flash(f"Application {status}", "success")
    return redirect(url_for('admin_dashboard'))


@app.route('/resume/<filename>')
@login_required
def view_resume(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# ================= USER ACCOUNT PAGES =================

@app.route('/my-applications')
@login_required
def my_applications_menu():
    return redirect(url_for('jobs'))  # reuse existing logic


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.username = request.form['username']
        db.session.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html')


@app.route('/account-security', methods=['GET', 'POST'])
@login_required
def account_security():
    if request.method == 'POST':
        if not check_password_hash(
            current_user.password,
            request.form['current_password']
        ):
            flash("Current password incorrect", "danger")
            return redirect(url_for('account_security'))

        current_user.password = generate_password_hash(
            request.form['new_password']
        )
        db.session.commit()
        flash("Password updated successfully", "success")
        return redirect(url_for('account_security'))

    return render_template('account_security.html')


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

# ================= LOGOUT =================

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ================= INIT =================
with app.app_context():
    db.create_all()

    if not Job.query.filter_by(job_type="platform").first():
        default_jobs = [
            Job(title="Python Developer", company="HireFlow", description="Python, Flask, APIs", job_type="platform"),
            Job(title="Frontend Developer", company="HireFlow", description="HTML, CSS, JS", job_type="platform"),
            Job(title="Data Analyst", company="HireFlow", description="SQL, Excel, Power BI", job_type="platform"),
            Job(title="Cyber Security Analyst", company="HireFlow", description="SOC, SIEM, Threat Analysis", job_type="platform"),
        ]
        db.session.add_all(default_jobs)

    if not User.query.filter_by(username="admin").first():
        db.session.add(User(
            username="admin",
            password=generate_password_hash("admin123"),
            role="admin"
        ))

    if not User.query.filter_by(username="company1").first():
        db.session.add(User(
            username="company1",
            password=generate_password_hash("company123"),
            role="company"
        ))

    db.session.commit()


if __name__ == "__main__":
    app.run(debug=True)
