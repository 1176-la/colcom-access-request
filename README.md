# colcom-access-request
user access
# app.py
import os
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)

# Configuration
# Use a secret key for session management (IMPORTANT: Change this in production)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_colcom_foods')
# Configure SQLite database (for simplicity, can be changed to PostgreSQL/MySQL)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///colcom_access.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirects to login page if user is not logged in

# --- Database Models ---

class User(UserMixin, db.Model):
    """
    User model representing employees in Colcom Foods.
    Roles: 'applicant', 'dept_manager', 'ict_executive', 'ict_team'
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='applicant') # e.g., 'applicant', 'dept_manager', 'ict_executive', 'ict_team'
    department = db.Column(db.String(100), nullable=True) # Department of the user

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class AccessRequest(db.Model):
    """
    Model for an access request.
    Statuses:
    - 'PENDING_DEPT_MANAGER': Awaiting approval from the applicant's department manager.
    - 'PENDING_ICT_EXECUTIVE': Awaiting approval from the ICT Executive.
    - 'PENDING_ICT_TEAM': Awaiting action from the ICT Team.
    - 'APPROVED': Request has been fully approved and actioned by ICT.
    - 'DENIED': Request has been denied at some stage.
    """
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    applicant = db.relationship('User', backref=db.backref('access_requests', lazy=True))

    # Updated fields for specific resource types
    resource_type = db.Column(db.String(100), nullable=False) # e.g., 'Meat Matrix', 'Dynamics 365', 'Internet Access', 'BYOD Access', 'Domain Access'
    resource_requested = db.Column(db.String(200), nullable=True) # General description, can be null if resource_type is specific
    reason = db.Column(db.Text, nullable=False)
    
    # Policy fields for specific resource types
    internet_policy = db.Column(db.Text, nullable=True) # For 'Internet Access'
    byod_policy = db.Column(db.Text, nullable=True) # For 'BYOD Access'

    status = db.Column(db.String(50), nullable=False, default='PENDING_DEPT_MANAGER')
    
    # Approval fields for Department Manager
    dept_manager_approved = db.Column(db.Boolean, default=None) # True/False/None
    dept_manager_approval_date = db.Column(db.DateTime, nullable=True)
    dept_manager_justification = db.Column(db.Text, nullable=True)
    dept_manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    dept_manager_user = db.relationship('User', foreign_keys=[dept_manager_id], backref='approved_as_dept_manager')

    # Approval fields for ICT Executive
    ict_executive_approved = db.Column(db.Boolean, default=None)
    ict_executive_approval_date = db.Column(db.DateTime, nullable=True)
    ict_executive_justification = db.Column(db.Text, nullable=True)
    ict_executive_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ict_executive_user = db.relationship('User', foreign_keys=[ict_executive_id], backref='approved_as_ict_executive')

    # Actioned by ICT Team
    ict_team_actioned = db.Column(db.Boolean, default=False)
    ict_team_action_date = db.Column(db.DateTime, nullable=True)
    ict_team_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ict_team_user = db.relationship('User', foreign_keys=[ict_team_id], backref='actioned_by_ict_team')

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<AccessRequest {self.id} - {self.resource_type} - {self.status}>'

# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database given their ID."""
    return db.session.get(User, int(user_id))

# --- Role-based Access Control Decorators ---

def role_required(allowed_roles):
    """
    Decorator to restrict access to certain routes based on user roles.
    `allowed_roles` should be a list of roles (e.g., ['dept_manager', 'ict_executive']).
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            if current_user.role not in allowed_roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard')) # Or a more appropriate unauthorized page
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Routes ---

@app.route('/')
@login_required
def dashboard():
    """
    Main dashboard for users.
    Shows applicant's requests, and pending approvals for managers/ICT.
    """
    user_requests = AccessRequest.query.filter_by(applicant_id=current_user.id).order_by(AccessRequest.created_at.desc()).all()
    
    pending_approvals = []
    if current_user.role == 'dept_manager':
        # Find requests from users in the same department, pending dept manager approval
        # This assumes a dept manager only approves for their own department.
        # A more robust system might have a direct link between manager and managed users.
        # For simplicity, we'll assume a dept manager can see all pending dept manager requests.
        # In a real system, you'd filter by applicant's department matching manager's department.
        pending_approvals = AccessRequest.query.filter_by(status='PENDING_DEPT_MANAGER').all()
    elif current_user.role == 'ict_executive':
        pending_approvals = AccessRequest.query.filter_by(status='PENDING_ICT_EXECUTIVE').all()
    elif current_user.role == 'ict_team':
        pending_approvals = AccessRequest.query.filter_by(status='PENDING_ICT_TEAM').all()

    return render_template('dashboard.html', user_requests=user_requests, pending_approvals=pending_approvals)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'applicant') # Default to applicant
        department = request.form.get('department')

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            new_user = User(username=username, role=role, department=department)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/create_request', methods=['GET', 'POST'])
@login_required
@role_required(['applicant']) # Only applicants can create requests
def create_request():
    """Handles creation of new access requests."""
    if request.method == 'POST':
        resource_type = request.form['resource_type']
        resource_requested = request.form.get('resource_requested') # Can be None if specific type selected
        reason = request.form['reason']
        internet_policy = request.form.get('internet_policy')
        byod_policy = request.form.get('byod_policy')

        new_request = AccessRequest(
            applicant_id=current_user.id,
            resource_type=resource_type,
            resource_requested=resource_requested,
            reason=reason,
            internet_policy=internet_policy if resource_type == 'Internet Access' else None,
            byod_policy=byod_policy if resource_type == 'BYOD Access' else None,
            status='PENDING_DEPT_MANAGER' # Initial status
        )
        db.session.add(new_request)
        db.session.commit()
        flash('Access request submitted successfully! It is now pending your department manager\'s approval.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_request.html')

@app.route('/request_detail/<int:request_id>', methods=['GET', 'POST'])
@login_required
def request_detail(request_id):
    """
    Displays details of an access request and allows managers/ICT to approve/deny/action.
    """
    access_request = db.session.get(AccessRequest, request_id)

    if not access_request:
        flash('Request not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Ensure only relevant users can view/act on the request
    can_view = False
    can_act = False
    justification_required = False

    if current_user.id == access_request.applicant_id:
        can_view = True
    elif current_user.role == 'dept_manager' and access_request.status == 'PENDING_DEPT_MANAGER':
        # In a real system, you'd check if the dept manager is responsible for the applicant's department
        can_view = True
        can_act = True
        justification_required = True # Justification always required for deny
    elif current_user.role == 'ict_executive' and access_request.status == 'PENDING_ICT_EXECUTIVE':
        can_view = True
        can_act = True
        justification_required = True
    elif current_user.role == 'ict_team' and access_request.status == 'PENDING_ICT_TEAM':
        can_view = True
        can_act = True # ICT team actions, not approves/denies in the same way
    elif current_user.role == 'ict_executive' and access_request.status in ['APPROVED', 'DENIED', 'PENDING_ICT_TEAM']:
        # ICT Executive can view all requests after their stage or final
        can_view = True
    elif current_user.role == 'ict_team' and access_request.status in ['APPROVED', 'DENIED']:
        # ICT Team can view all requests after their stage or final
        can_view = True

    if not can_view:
        flash('You do not have permission to view this request.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST' and can_act:
        action = request.form.get('action') # 'approve', 'deny', 'actioned'
        justification = request.form.get('justification')

        if current_user.role == 'dept_manager' and access_request.status == 'PENDING_DEPT_MANAGER':
            if action == 'approve':
                access_request.dept_manager_approved = True
                access_request.dept_manager_approval_date = datetime.utcnow()
                access_request.dept_manager_id = current_user.id
                access_request.status = 'PENDING_ICT_EXECUTIVE'
                flash('Request approved by Department Manager. Now pending ICT Executive approval.', 'success')
            elif action == 'deny':
                if not justification:
                    flash('Justification is required for denying the request.', 'danger')
                    return render_template('request_detail.html', access_request=access_request, can_act=can_act, justification_required=justification_required)
                access_request.dept_manager_approved = False
                access_request.dept_manager_approval_date = datetime.utcnow()
                access_request.dept_manager_justification = justification
                access_request.dept_manager_id = current_user.id
                access_request.status = 'DENIED'
                flash('Request denied by Department Manager.', 'info')
            else:
                flash('Invalid action.', 'danger')

        elif current_user.role == 'ict_executive' and access_request.status == 'PENDING_ICT_EXECUTIVE':
            if action == 'approve':
                access_request.ict_executive_approved = True
                access_request.ict_executive_approval_date = datetime.utcnow()
                access_request.ict_executive_id = current_user.id
                access_request.status = 'PENDING_ICT_TEAM'
                flash('Request approved by ICT Executive. Now pending ICT Team action.', 'success')
            elif action == 'deny':
                if not justification:
                    flash('Justification is required for denying the request.', 'danger')
                    return render_template('request_detail.html', access_request=access_request, can_act=can_act, justification_required=justification_required)
                access_request.ict_executive_approved = False
                access_request.ict_executive_approval_date = datetime.utcnow()
                access_request.ict_executive_justification = justification
                access_request.ict_executive_id = current_user.id
                access_request.status = 'DENIED'
                flash('Request denied by ICT Executive.', 'info')
            else:
                flash('Invalid action.', 'danger')

        elif current_user.role == 'ict_team' and access_request.status == 'PENDING_ICT_TEAM':
            if action == 'actioned':
                access_request.ict_team_actioned = True
                access_request.ict_team_action_date = datetime.utcnow()
                access_request.ict_team_id = current_user.id
                access_request.status = 'APPROVED' # Final status after actioned
                flash('Request actioned by ICT Team. Request is now complete.', 'success')
            else:
                flash('Invalid action for ICT Team.', 'danger')
        else:
            flash('You cannot perform this action at this stage or with your role.', 'danger')
            return redirect(url_for('dashboard'))

        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('request_detail.html', access_request=access_request, can_act=can_act, justification_required=justification_required)

@app.route('/reports')
@login_required
@role_required(['ict_executive', 'ict_team']) # Only ICT roles can view reports
def reports():
    """Generates and displays reports and analytics."""
    all_requests = AccessRequest.query.order_by(AccessRequest.created_at.asc()).all()

    total_requests = len(all_requests)
    approved_requests = AccessRequest.query.filter_by(status='APPROVED').count()
    denied_requests = AccessRequest.query.filter_by(status='DENIED').count()

    # Requests per day
    requests_per_day = {}
    for req in all_requests:
        date_str = req.created_at.strftime('%Y-%m-%d')
        requests_per_day[date_str] = requests_per_day.get(date_str, 0) + 1
    
    # Convert to a list of (date, count) tuples for easier rendering
    requests_per_day_list = sorted(requests_per_day.items())

    return render_template('reports.html',
                           total_requests=total_requests,
                           approved_requests=approved_requests,
                           denied_requests=denied_requests,
                           requests_per_day=requests_per_day_list)

# --- Database Initialization ---

@app.before_first_request
def create_tables():
    """Creates database tables and a few default users if they don't exist."""
    db.create_all()
    
    # Create default users if they don't exist
    if not User.query.filter_by(username='applicant1').first():
        applicant1 = User(username='applicant1', role='applicant', department='Sales')
        applicant1.set_password('password')
        db.session.add(applicant1)
    
    if not User.query.filter_by(username='manager1').first():
        manager1 = User(username='manager1', role='dept_manager', department='Sales')
        manager1.set_password('password')
        db.session.add(manager1)

    if not User.query.filter_by(username='ict_exec').first():
        ict_exec = User(username='ict_exec', role='ict_executive', department='ICT')
        ict_exec.set_password('password')
        db.session.add(ict_exec)

    if not User.query.filter_by(username='ict_team1').first():
        ict_team1 = User(username='ict_team1', role='ict_team', department='ICT')
        ict_team1.set_password('password')
        db.session.add(ict_team1)
    
    db.session.commit()
    print("Database tables created and default users added.")

# --- Run the application ---
if __name__ == '__main__':
    # This is for development. For production, use a WSGI server like Gunicorn/Nginx.
    app.run(debug=True)

