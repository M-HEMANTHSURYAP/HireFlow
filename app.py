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

from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

# ================= BASIC CONFIG =================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
# ✅ FIXED
db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url

app.config['UPLOAD_FOLDER'] = 'uploads'

# ================= MAIL CONFIG =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

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
    archived_by_user = db.Column(db.Boolean, default=False)


# ✅ NEW MODEL: Notifications (STEP 1)
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================= HELPERS =================
from functools import wraps

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            return "Access Denied", 403
        return func(*args, **kwargs)
    return wrapper


def company_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role != "company":
            return "Access Denied", 403
        return func(*args, **kwargs)
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

    # Show only non-archived applications on jobs page
    applications = {
        a.job_id: a.status
        for a in Application.query
        .filter_by(user_id=current_user.id, archived_by_user=False)
        .all()
    }

    # ✅ ADDITION: track ALL jobs ever applied (including archived)
    applied_job_ids = [
        a.job_id
        for a in Application.query
        .filter_by(user_id=current_user.id)
        .all()
    ]

    return render_template(
        'jobs.html',
        company_jobs=company_jobs,
        platform_jobs=platform_jobs,
        applications=applications,
        applied_job_ids=applied_job_ids   # ✅ PASS TO TEMPLATE
    )


@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required
def apply(job_id):
    job = Job.query.get_or_404(job_id)

    # 🔒 HARD BLOCK: prevent re-apply even if archived
    existing = Application.query.filter_by(
        user_id=current_user.id,
        job_id=job_id
    ).first()

    if existing:
        flash("You have already applied for this job", "warning")
        return redirect(url_for('jobs'))

    if request.method == 'POST':
        file = request.files['resume']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            db.session.add(Application(
                user_id=current_user.id,
                job_id=job_id,
                email=request.form['email'],
                resume_file=filename,
                archived_by_user=False
            ))
            db.session.commit()

            flash("Applied successfully", "success")
            return redirect(url_for('jobs'))

        flash("Only PDF allowed", "danger")

    return render_template('resume.html', job=job)


@app.route('/applications')
@login_required
def user_applications():
    # Show ALL applications (including archived) in My Applications
    applications = db.session.query(
        Application, Job
    ).join(Job, Application.job_id == Job.id) \
     .filter(Application.user_id == current_user.id) \
     .all()

    return render_template(
        'user_applications.html',
        applications=applications
    )


@app.route('/withdraw/<int:job_id>', methods=['POST'])
@login_required
def withdraw(job_id):
    application = Application.query.filter_by(
        user_id=current_user.id,
        job_id=job_id
    ).first_or_404()

    # 🚫 Cannot withdraw after shortlist
    if application.status == "Shortlisted":
        flash("Cannot withdraw after being shortlisted", "danger")
        return redirect(url_for('jobs'))

    # Withdraw = delete record
    db.session.delete(application)
    db.session.commit()

    flash("Application withdrawn successfully", "success")
    return redirect(url_for('jobs'))


@app.route('/archive/<int:job_id>', methods=['POST'])
@login_required
def archive(job_id):
    application = Application.query.filter_by(
        user_id=current_user.id,
        job_id=job_id,
        status="Shortlisted",
        archived_by_user=False
    ).first_or_404()

    # Archive = hide from jobs page ONLY
    application.archived_by_user = True
    db.session.commit()

    flash("Shortlisted message removed from view", "success")
    return redirect(url_for('jobs'))

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
@app.route('/company/platform-applications')
@login_required
@company_required
def company_platform_applications():
    applications = db.session.query(
        Application, User, Job
    ).join(User, Application.user_id == User.id) \
     .join(Job, Application.job_id == Job.id) \
     .filter(
         Job.job_type == "platform",
         Job.company == "HireFlow"
     ).all()

    return render_template(
        'company_applications.html',
        applications=applications
    )

@app.route('/company/applications')
@login_required
@company_required
def company_applications():
    # Get ONLY company-posted jobs (exclude platform jobs)
    jobs = Job.query.filter_by(
        company=current_user.username,
        job_type="company"
    ).all()

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

@app.route('/company/update_status/<int:app_id>/<status>')
@login_required
@company_required
def company_update_status(app_id, status):
    application = Application.query.get_or_404(app_id)
    job = Job.query.get_or_404(application.job_id)

    # ✅ ALLOW:
    # 1. Company-owned jobs
    # 2. Platform jobs (HireFlow)
    if job.job_type == "company" and job.company != current_user.username:
        return "Unauthorized", 403

    if status not in ["Shortlisted", "Rejected"]:
        return "Invalid status", 400

    application.status = status
    db.session.commit()

    flash(f"Candidate {status}", "success")

    # 🔁 Redirect back correctly
    if job.job_type == "platform":
        return redirect(url_for('company_platform_applications'))

    return redirect(url_for('company_applications'))

# ================= ADMIN =================

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():

    # ONLY pending company job requests
    job_requests = JobRequest.query.filter_by(status="Pending").all()

    return render_template(
        'admin.html',
        job_requests=job_requests
    )



# ✅ FIXED: ADMIN HISTORY ROUTE
@app.route('/admin/history')
@login_required
@admin_required
def admin_history():
    applications = db.session.query(
        Application, User, Job
    ).join(User, Application.user_id == User.id)\
     .join(Job, Application.job_id == Job.id)\
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

    if status not in ["Shortlisted", "Rejected"]:
        flash("Invalid status", "danger")
        return redirect(url_for('admin_dashboard'))

    application.status = status
    db.session.commit()

    # ✅ ONLY if shortlisted
    if status == "Shortlisted":
        job = Job.query.get(application.job_id)
        user = User.query.get(application.user_id)

        # 🔐 SAFETY CHECK (THIS FIXES 500 ERROR)
        if job and user:
            message = (
                f"🎉 CONGRATS! Dear {user.username}, "
                f"your application for '{job.title}' has been shortlisted."
            )

            db.session.add(Notification(
                user_id=user.id,
                message=message
            ))
            db.session.commit()

            # 📧 Email (safe)
            try:
                msg = Message(
                    subject="🎉 You’ve been Shortlisted – HireCoreX",
                    recipients=[application.email] if application.email else [],
                    body=f"""
Dear {user.username},

Congratulations! 🎉

Your application for the role "{job.title}" has been shortlisted.

The hiring team will contact you soon.

Best regards,
HireCoreX Team
"""
                )
                mail.send(msg)
            except Exception as e:
                print("Email error:", e)

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
@app.context_processor
def inject_notifications():
    if not current_user.is_authenticated or current_user.role != "user":
        return {}

    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).all()

    unread_count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).count()

    return dict(
        notifications=notifications,
        unread_count=unread_count
    )

@app.route('/notifications/read/<int:notif_id>')
@login_required
def mark_notification_read(notif_id):
    notif = Notification.query.get_or_404(notif_id)

    if notif.user_id != current_user.id:
        return "Unauthorized", 403

    notif.is_read = True
    db.session.commit()
    return redirect(request.referrer or url_for('jobs'))

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
