from flask import Flask, request, render_template, flash, redirect, url_for, session, abort, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_uploads import UploadSet, configure_uploads, IMAGES
import random
import string
from authlib.integrations.flask_client import OAuth
import logging
from flask_session import Session
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
import hashlib
import requests
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask_migrate import Migrate
from flask_socketio import SocketIO
import flask_monitoringdashboard as Dashboard
import csv




app = Flask(__name__)
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_BINDS'] = {
    'admins': os.getenv('SQLALCHEMY_BINDS_ADMIN'),
    'teachers': 'sqlite:///teachers.db',
    'it_quiz': 'sqlite:///it_quiz.db',
    'squiz': 'sqlite:///squiz.db',
    'upload': 'sqlite:///upload.db',
    'class': 'sqlite:///class.db',
    're': 'sqlite:///re.db',
    'attendance': 'sqlite:///attendance.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOADED_IMAGES_DEST'] = 'static/uploads'
app.config['SERVER_NAME'] = '127.0.0.1:5000'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['WTF_CSRF_ENABLED'] = True



images = UploadSet('images', IMAGES)
configure_uploads(app, images)

bcrypt = Bcrypt(app)
oauth = OAuth(app)
csrf =CSRFProtect(app)
db = SQLAlchemy(app)
socket = SocketIO(app)
migrate = Migrate(app,db)
mail = Mail(app)

Dashboard.bind(app)
  # Set your desired password
  # Disable CSRF for specific routes


def generate_nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def generate_csrf_token():
    csrf_token = hashlib.sha256(os.urandom(64)).hexdigest()
    session['_csrf_token'] = csrf_token
    return csrf_token

@app.route('/static/js/OneSignalSDKWorker.js')
def serve_worker():
    response = send_from_directory('static/js', 'OneSignalSDKWorker.js')
    response.headers['Service-Worker-Allowed'] = '/'
    return response

google = oauth.register(
    name='google',
    
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

linkedin = oauth.register(
    'linkedin',
    request_token_params={'scope': 'openid profile email'},
    base_url='https://api.linkedin.com/v1/',
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/uas/oauth/accessToken',
    authorize_url='https://www.linkedin.com/uas/oauth/authenticate'
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Tclass(db.Model,UserMixin):
    __tablename__ = 'tclass'
    __bind_key__ = 'class'  # Ties the model to the 'class' database
    
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    teacher = db.Column(db.String(255), nullable=False)  # Teacher's name (optional)
    fees = db.Column(db.Float, nullable=False)
    grade = db.Column(db.String(255), nullable=False)
    time = db.Column(db.String(255), nullable=False)
    date = db.Column(db.String(255), nullable=False)  # Day of the week
    image_path = db.Column(db.String(255), nullable=True)  # Path to the image
    teacher_id = db.Column(db.Integer, nullable=False)  # Store teacher's ID without foreign key
    zoom_link = db.Column(db.String(255), nullable=True)
    exam_link = db.Column(db.String(255), nullable=True)
    quiz_link = db.Column(db.String(255), nullable=True)
    

class User(db.Model, UserMixin):
    __tablename__ = 'user'
   
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    grade = db.Column(db.Integer, nullable=False)
    t_no = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=True, unique=True)
    NIC = db.Column(db.String, nullable=True)
    pic = db.Column(db.String, nullable=True)
    status = db.Column(db.Integer, default=0, nullable=False)
    it_score = db.Column(db.Integer, default=0, nullable=True)
    science_score = db.Column(db.Integer, default=0, nullable=True)
    missed_classes = db.Column(db.Integer, default=0, nullable=True)

class Attendance(db.Model):
    __bind_key__='attendance'
    __tablename__ = 'attendance'
    
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.Integer,nullable = True)
    user_id = db.Column(db.Integer, nullable=False)  # No foreign key constraint
    zoom_id = db.Column(db.String, nullable=False)
    attended_date = db.Column(db.Date, nullable=False)
    


class Admin(db.Model, UserMixin):
    __bind_key__ = 'admins'
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)


class Teacher(db.Model,UserMixin):
    __bind_key__ = 'teachers'  # This binds the model to the 'teachers' database
    __tablename__ = 'teachers'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    common_name = db.Column(db.String(100), nullable=True)
    grade = db.Column(db.String(50), nullable=True)
    status = db.Column(db.Integer, default=1)
    pic = db.Column(db.String(200), nullable=True)
    NIC = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    fees = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    pic = db.Column(db.String(100), nullable=True)
    qualifications = db.Column(db.String(100), nullable=True)

class ItQuiz(db.Model):
    __bind_key__ = 'it_quiz'  # Binds this model to the 'it_quiz' database
    __tablename__ = 'it_quiz'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)


class Squiz(db.Model):
    __bind_key__ = 'squiz'  # Binds this model to the 'squiz' database
    __tablename__ = 'squiz'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)


class Upload(db.Model):
    __bind_key__ = 'upload'  # Binds this model to the 'upload' database
    __tablename__ = 'upload'
    id = db.Column(db.Integer, primary_key=True)
    tute_name = db.Column(db.String(255), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    
class Receipt(db.Model):
    __bind_key__ = 're'  # Binds this model to the 'upload' database
    __tablename__ = 're'

    id = db.Column(db.Integer, primary_key=True)
    student_name = db.Column(db.String(100), nullable=False)
    class_id = db.Column(db.Integer, nullable=False)
    receipt_image = db.Column(db.String(150), nullable=True)
    status = db.Column(db.String(50), default="Pending")  # 'Pending' or 'Approved'
    payment_date = db.Column(db.String,nullable = False)


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id)) or Teacher.query.get(int(user_id))
    return user



def send_registration_email(user_email):
    subject = 'Welcome to Our Flask App'
    content = 'Thank you for registering with our Flask app!'

    message = Mail(
        from_email='nerosense124@gmail.com',  # Sender email
        to_emails=user_email,  # Recipient email
        subject=subject,
        plain_text_content=content
    )

    try:
        # Initialize SendGrid client and send the email
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"Email sent successfully! Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending email: {e}")

def send_reminder_email(user_email, first_name, last_name, missed_classes):
    subject = f'Attendance Reminder: {first_name} {last_name}, You\'ve Missed {missed_classes} Classes'
    
    content = (
        f'Dear {first_name} {last_name},\n\n'
        f'We noticed that you have missed {missed_classes} classes. Regular attendance is important to '
        f'keep up with the course content and ensure academic success. Please make sure to attend your upcoming classes.\n\n'
        'If you need any assistance or have questions about the course, feel free to reach out to us.\n\n'
        'Thank you for your attention, and we look forward to seeing you in class soon.\n\n'
        'Best regards,\nYour School Administration'
    )

    message = Mail(
        from_email='nerosense124@gmail.com',  # Sender email
        to_emails=user_email,  # Recipient email
        subject=subject,
        plain_text_content=content
    )

    try:
        # Send the email using SendGrid API
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"Reminder email sent to {user_email}! Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending email to {user_email}: {e}")

@app.route('/')
def main():
    return render_template('main.html')

@app.route('/register', methods=['GET', 'POST'])
def reg():
    if request.method == 'POST':
        first_name = request.form['f_name']
        last_name = request.form['l_name']
        grade = request.form['grade']
        t_no = request.form['t_no']
        email = request.form['email']
        password = request.form['password']
        c_password = request.form['password2']
        nic = request.form['NIC']
        
        if password != c_password:
            flash('Passwords do not match!')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return render_template('register.html')

        hashed_password = bcrypt.generate_password_hash(password, rounds=12)
        user = User(password=hashed_password, email=email, NIC=nic, first_name=first_name, last_name=last_name, grade=grade, t_no=t_no)
        db.session.add(user)
        db.session.commit()
        send_registration_email(email)
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ema = request.form['email']
        pas = request.form['password']

        if ema and pas:
            # Check in the User table
            user = User.query.filter_by(email=ema).first()
            if user:
                if user.status == 1:
                    if bcrypt.check_password_hash(user.password, pas):
                        login_user(user)
                        flash('Login successful as User','success')
                        return redirect(url_for('lass'))  # Redirect to user dashboard
                    else:
                        flash("Incorrect password")
                else:
                    flash("Account pending approval")
            else:
                # Check in the Teacher table if not found in User
                teacher = Teacher.query.filter_by(email=ema).first()
                if teacher:
                    if bcrypt.check_password_hash(teacher.password, pas):
                        login_user(teacher)
                        print(current_user.id,'logged in successfully a s teacher')
                        flash('Login successful as Teacher','success')
                        return redirect(url_for('teacher_profile'))  # Redirect to teacher dashboard
                    else:
                        flash("Incorrect password for Teacher account",'danger')
                else:
                    flash("Account does not exist in either User or Teacher database",'danger')
        else:
            flash('Please fill in both fields')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('main'))

@app.route('/profile')
@login_required
def profile():
   
    return render_template('profile.html')

@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    return render_template('update.html')

@app.route('/backtoprofile')
def backtoprofile():
    return redirect(url_for('profile'))

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

@app.route('/updateprofile', methods=['POST', 'GET'])
@login_required
def updateprofile():
    if request.method == 'POST':
        pd = User.query.get(current_user.id)

        fn = request.form['first_name']
        ln = request.form['last_name']
        ga = request.form['grade']
        nic = request.form['nic']
        tn = request.form['t_no']
        em = request.form['email']
        pa = request.form['password']
        pic = request.files.get('reciept')

        if pa:
            hashed_password = bcrypt.generate_password_hash(pa).decode('utf-8')
            pd.password = hashed_password

        if pic and '.' in pic.filename:
            ext = pic.filename.rsplit('.', 1)[1].lower()
            if ext in ALLOWED_EXTENSIONS:
                filename = secure_filename(pic.filename)
                pic.save(os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename))
                pd.pic = filename
            else:
                flash('Only JPG, JPEG, and PNG files are allowed.')
                return redirect(url_for('update'))

        pd.first_name = fn
        pd.last_name = ln
        pd.grade = ga
        pd.NIC = nic
        pd.t_no = tn
        pd.email = em

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
            return render_template('update.html')
    return render_template('update.html')

@app.route('/adminlogin')
def adminlogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if bcrypt.check_password_hash(user.password, password):
            user = Admin.query.get(username=username).first()
            if user:
                login_user(admin)
                return redirect('admin')
            else:
                flash('Invalid admin username')
        else:
            flash('Please fill in both fields')
    return render_template('admin/adminlogin.html')

@app.route('/admin')
def admin():
    return render_template('admin/welcome.html')

@app.route('/logoutadmin')
def logoutadmin():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    total_user = User.query.count()
    total_approved = User.query.filter_by(status=1).count()
    total_pending = User.query.filter_by(status=0).count()
    return render_template('admin/admindashboard.html', title="Admin Dashboard", 
                           total_user=total_user, total_approved=total_approved, total_pending=total_pending)

@app.route('/admin/get-all-user', methods=["POST", "GET"])
@csrf.exempt
def admin_get_all_user():
    search = request.form.get('search') if request.method == "POST" else None
    users = User.query.filter(User.first_name.like(f'%{search}%')).all() if search else User.query.all()
    return render_template('admin/all.html', title='Approve User', users=users)

@app.route('/admin/approve-user/<int:id>')
def admin_approve(id):
    user = User.query.get(id)
    if user:
        user.status = 1
        db.session.commit()
        flash('User approved successfully', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin_get_all_user'))
#
@app.route('/login/google')
def login_google():
    # Generate and store the nonce in the session
    nonce = generate_nonce()
    session['nonce'] = nonce  # Store the nonce in the session
    
    redirect_uri = url_for('auth', _external=True)
    
    # Pass the nonce in the authorization request
    return google.authorize_redirect(redirect_uri, nonce=nonce)
@app.route('/authorized/google')
def auth():
    try:
        # Retrieve the nonce from the session
        nonce = session.get('nonce')
        
        # Get the Google account info
        token = google.authorize_access_token()
        
        # Parse and validate the ID token using the nonce
        user_info = google.parse_id_token(token, nonce=nonce)
        print(user_info)  
       
        user = User.query.filter_by(email=user_info['email']).first()
        if user :
            if user.status == 1:
                login_user(user)
                flash(' login successful','success')
                return redirect(url_for('lass'))
            else:
                flash('pending approval')
                return redirect(url_for('login'))
        else:
            return redirect(url_for('reg'))    
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('login'))
    
from sqlalchemy import text

def create_db_without_foreign_keys():
    with app.app_context():
        db.create_all()
        

# Run the database creation
create_db_without_foreign_keys()











@app.route('/quiz')
def quizmain():
    return render_template('quiz/quizmain.html')
@app.route('/it quiz')
def it():
    itquiz = ItQuiz.query.all()
    return render_template('quiz/itquiz.html',itquiz=itquiz)

@app.route('/it_quiz/score', methods=['GET', 'POST'])
def itscore():
    if request.method == 'POST':
        print("Form submitted via POST!")
        score = 0
        it = ItQuiz.query.all()
        for index,question in enumerate(it,start = 1):
            answer = request.form.get(f'question{index}')
            if answer == question.correct_answer:
                score += 1
       
        user = User.query.filter_by(id = current_user.id).first()
        if user:
            user.it_score = score
            db.session.commit()

        print(f"Final score: {score}")
        return f'Your score is {score} out of 25.'
    else:
        print("Accessing form via GET request")
        return render_template('quiz/itquiz.html')  
    
    
@app.route('/it_quiz/back',methods = ['GET'])
def itback():
    return redirect(url_for('quizmain'))






@app.route('/squiz/main')
def sciequiz():
    squiz = Squiz.query.all()
    return render_template('squiz/squiz.html',squiz=squiz)

@app.route('/squiz/score', methods=['GET', 'POST'])
def scienscore():
    if request.method == 'POST':
        
        score = 0
        sa = Squiz.query.all()
        for index,question in enumerate(sa,start = 1):
            answer = request.form.get(f'question{index}')
            if answer == question.correct_answer:
                score += 1
       
        user = User.query.filter_by(id = current_user.id).first()
        if user:
            user.science_score = score
            db.session.commit()



        print(f"Final score: {score}")
        return f'Your score is {score} out of 25.'
    else:
        print("Accessing form via GET request")
        return render_template('squiz/squiz.html')  
# Run the database creation

@app.route('/added',methods =['GET','POST'])
@csrf.exempt
def add_teachers():
    if request.method == 'GET':
       return render_template('teachers/register.html')
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        grade = request.form['grade']
        t_no = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        fees = request.form['fees']
        nic = request.form['NIC']
        common = request.form['common_name']
        f_name = f'{first_name}{last_name}'
        subject = request.form['subject']
        
        
        hashed_password = bcrypt.generate_password_hash(password,rounds=12)
        
        teacher = Teacher.query.filter_by(email=email).first()
        if teacher is None:
            teacher = Teacher(
                first_name =first_name,
                last_name=last_name,
                grade=grade,
                NIC= nic,
                full_name = f_name,
                common_name = common,
                email = email,
                password = hashed_password,
                phone = t_no,
                fees = fees,
                subject = subject
                )
            db.session.add(teacher)
            db.session.commit()
            send_registration_email(email)
            flash('teacher registration successful','success')
            return redirect(url_for('add_teachers'))
        else:
            flash('email already taken')
            return redirect(url_for('add_teachers'))

@app.route('/addquiz' ,methods = ['GET','POST'])
@csrf.exempt
def addquiz():
    if request.method =='GET':
        return render_template('admin/addquiz.html')
    if request.method == 'POST':
        ques = request.form['question']
        op1 = request.form['option1']
        op2 = request.form['option2']
        op3 = request.form['option3']
        ca = request.form['correct_answer']

        itquiz= ItQuiz.query.filter_by(question = ques).first()
        if itquiz is None:
            itquiz = ItQuiz(question=ques,option1 =op1,option2=op2,option3 = op3,correct_answer = ca)
            db.session.add(itquiz)
            db.session.commit()
            return redirect(url_for('addquiz'))
        else:
            return 'hello'
@app.route('/view', methods=['GET', 'POST'])
@csrf.exempt
def view():
    if request.method == 'GET':
        return render_template('teachers/se_te.html')  # This renders the page with subject and grade selection
    
    if request.method == 'POST':
        subject = request.form['category']  # Get the selected subject
        grade = request.form['branch']  # Get the selected grade
        if grade == '1':
            grade =10        # Initialize the teacher query
        teacher_query = None
        
        # Filter teachers based on subject and grade
        if subject == '1':  # Assuming '1' is for 'Science'
            teacher_query = Teacher.query.filter_by(subject='science', grade=grade).all()
        elif subject == '2':  # Assuming '2' is for 'IT'
            teacher_query = Teacher.query.filter_by(subject='it', grade=grade).all()

        # If there are teachers, pass them to the template
        if teacher_query:
            print('yes')
            return render_template('teachers/teachers.html', teachers=teacher_query)  # Pass teachers to the template
        else:
            print('none')
            print(grade)
            return render_template('teachers/se_te.html', teachers=None, message="No teachers found for this subject and grade.")

        
@app.route('/upload',methods = ['GET','POST'])
@csrf.exempt
def upload():
    if request.method == 'GET':
        return render_template('admin/upload.html')
    if request.method == 'POST':
        title = request.form['title']
       
        description = request.form['description']
        file = request.files['file']

        if file:
            filename = os.path.join(app.config['UPLOADED_IMAGES_DEST'],file.filename)
            file.save(filename)

        upload_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_tutorial = Upload(
                tute_name=title,
                file_name=file.filename,
                upload_date=upload_date,
                description=description,
               
            )
            
            # Add the new tutorial to the database and commit
        db.session.add(new_tutorial)
        db.session.commit()
            
        return redirect(url_for('display_tutorials'))

@app.route('/downloads/<filename>')
def download_file(filename):
    directory = app.config['UPLOADED_IMAGES_DEST']
    return send_from_directory(directory, filename, as_attachment=True)
    


# Route to display all tutorials
@app.route('/tutes')
def display_tutorials():
   
    tutorials = Upload.query.all()  # Get all tutorials from the database
    return render_template('tutes.html', tutorials=tutorials )

@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if request.method == 'POST':
        # Get form data
        subject = request.form['subject']
        teacher = request.form['teacher']
        fees = float(request.form['fees'])
        grade = request.form['grade']
        time = request.form['time']
        day_of_week = request.form['day_of_week']  # Get the selected day of the week

        # Handle image upload
        pic = request.files['image']
        if pic and '.' in pic.filename:
            ext = pic.filename.rsplit('.', 1)[1].lower()
            if ext in ALLOWED_EXTENSIONS:
                filename = secure_filename(pic.filename)
                pic.save(os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename))
                image_path = filename
            else:
                flash('Only JPG, JPEG, and PNG files are allowed.')
                return redirect(url_for('add_class'))  # Fallback image if none is uploaded

        # Insert new class data into the database
        new_class = Tclass(
            subject=subject,
            teacher=teacher,
            fees=fees,
            grade=grade,
            time=time,
            date=day_of_week,  # Store the selected day of the week
            image_path=image_path
        )
        
        db.session.add(new_class)
        db.session.commit()
        print('new class added')
        flash('new class added')
        return redirect(url_for('lass'))  # Redirect to home page after adding the class

    return render_template('admin/add.html')
@app.route('/class',methods = ['GET','POST'])
@csrf.exempt
def lass():
    # Fetch all classes from the database
    
    search = request.form.get('search') if request.method == 'POST' else None
    classes = Tclass.query.filter(Tclass.subject.like(f'%{search}%')).all() if search else Tclass.query.all()

    return render_template('common/classes.html', classes=classes)

@app.route('/class/<int:class_id>')
def class_details(class_id):
    # Fetch the class data based on the class_id
    class_data = Tclass.query.get(class_id)
    stud = current_user.first_name
    stu = Receipt.query.filter_by(student_name = stud).first()
    
    # Pass the class data to the template with a different variable name
    return render_template('common/class.html', class_data=class_data,stu = stu)

@app.route('/myclass/<int:class_id>')
def my_de(class_id):
    class_data = Tclass.query.get(class_id)
    return render_template('common/myclass.html', class_data=class_data)

@app.route('/payment/<int:class_id>')
def payment(class_id):
    # Fetch the class details from the database using the class_id
    class_data = Tclass.query.get_or_404(class_id)
    
    # Pass the class data to the payment page
    return render_template('common/payment.html', class_data=class_data)




@app.route('/my_classes', methods=['GET'])
def my_classes():
    student_name = current_user.first_name  # Assuming we have a logged-in user
    receipts = Receipt.query.filter_by(student_name=student_name, status="Approved").all()
    
    # Collect class ids from the approved receipts
    paid_class_ids = [receipt.class_id for receipt in receipts]
    paid_classes = Tclass.query.filter(Tclass.id.in_(paid_class_ids)).all()
    
    return render_template('my_classes.html', classes=paid_classes)
@app.route('/add_receipt', methods=['GET', 'POST'])
@csrf.exempt
def add_receipt():
    if request.method == 'POST':
        student_name = request.form['student_name']
        class_id = request.form['class_id']
        payment_date = request.form['payment_date']

        # Call the function to add the receipt to the database
        new_receipt = Receipt(
            student_name=student_name,
            class_id=class_id,
            payment_date=payment_date,
            status="Pending"  # Default status is 'Pending'
        )
        
        # Add and commit to the database
        db.session.add(new_receipt)
        db.session.commit()

        return redirect(url_for('approve_receipts'))  # Redirect to a page to view receipts (create this route as needed)

    return render_template('add_receipt.html')
@app.route('/admin/approve_receipts', methods=['GET'])
@csrf.exempt
def approve_receipts():
    # Get all receipts with status 'Pending' 
    receipts = Receipt.query.filter_by(status="Pending").all()
    return render_template('approve_receipts.html', receipts=receipts)

@app.route('/admin/approve_receipt/<int:receipt_id>', methods=['POST'])
@csrf.exempt
def approve_receipt(receipt_id):
    receipt = Receipt.query.get_or_404(receipt_id)
    receipt.status = "Approved"
    db.session.commit()
    flash("Receipt approved successfully.")
    return redirect(url_for('approve_receipts'))
   # For Squiz database
 # Print all IT quiz questions created by this teacher

@app.route('/got to quiz/<int:class_id>')
def gotquiz(class_id):
    class_data = Tclass.query.get(class_id)
    return render_template('common/quiz.html',class_data = class_data)
@app.route('/got to exam/<int:class_id>')
def exam(class_id):
    class_data = Tclass.query.get(class_id)
    return render_template('common/exam.html',class_data = class_data)

@app.route('/teacher_profile')
@login_required 
def teacher_profile():
    teacher = Teacher.query.get(current_user.id)  # Assuming current_user is a Teacher
    return render_template('teacher/teacher_profile.html', teacher=teacher)


@app.route('/teacher_update', methods=['GET', 'POST'])
@login_required 
@csrf.exempt
def teacher_update():
    # Get the logged-in teacher's details
    teacher = Teacher.query.get(current_user.id)  # Assuming current_user is the logged-in teacher
    
    if request.method == 'POST':
        # 1. Update teacher's details from the form
        teacher.first_name = request.form.get('first_name')
        teacher.last_name = request.form.get('last_name')
        teacher.grade = request.form.get('grade')
        teacher.qualifications = request.form.get('qualifications')
        teacher.t_no = request.form.get('t_no')
        teacher.email = request.form.get('email')
        teacher.fees = request.form.get('fees')

        # 2. Handle password change (if provided)
        password = request.form.get('password')
        if password:
            hashed_password = bcrypt.generate_password_hash(password)
            teacher.password = hashed_password
        
        # 3. Handle profile picture upload
        pic = request.files.get('pic')
        if pic:
            # Ensure the file has an extension
            if '.' in pic.filename:
                ext = pic.filename.rsplit('.', 1)[1].lower()
                if ext in ALLOWED_EXTENSIONS:
                    # Save the picture securely
                    filename = secure_filename(pic.filename)
                    pic.save(os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename))  # Ensure 'UPLOADED_IMAGES_DEST' is set correctly in app config
                    teacher.pic = filename
                else:
                    flash('Only JPG, JPEG, and PNG files are allowed.', 'danger')
                    return redirect(url_for('teacher_update'))
            else:
                flash('Invalid file extension. Please upload an image file.', 'danger')
                return redirect(url_for('teacher_update'))
        
        # 4. Commit the changes to the database
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('teacher_profile'))
        except Exception as e:
            # Handle any errors that may occur during commit
            db.session.rollback()  # Rollback in case of any errors
            flash(f'An error occurred: {str(e)}', 'danger')
            return render_template('teacher/teacher_update.html', teacher=teacher)

    # Render the update form
    return render_template('teacher/teacher_update.html', teacher=teacher)

@app.route('/teacher/add_class', methods=['GET', 'POST'])
@login_required  # Ensure only logged-in teachers can add classes
def add_classs():
    if request.method == 'POST':
        teacher = request.form['teacher'] 
        subject = request.form['subject']
        fees = float(request.form['fees'])
        grade = request.form['grade']
        time = request.form['time']
        day_of_week = request.form['day_of_week']
        c = current_user.id
        # Handle image upload (optional)
        pic = request.files.get('image')
        image_path = None  # Default to None if no image is uploaded
        if pic and '.' in pic.filename:
            ext = pic.filename.rsplit('.', 1)[1].lower()
            if ext in ALLOWED_EXTENSIONS:
                filename = secure_filename(pic.filename)
                pic.save(os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename))
                image_path = filename
            else:
                flash('Only JPG, JPEG, and PNG files are allowed.', 'danger')
                return redirect(url_for('add_class'))
        print(f"Teacher ID: {c}")
        # Insert new class data into the database
        new_class = Tclass(
            subject=subject,
            teacher=teacher,  # Use teacher's name
            fees=fees,
            grade=grade,
            time=time,
            date=day_of_week,  # Store the selected day of the week
            image_path=image_path,
            teacher_id=c  # Directly assign the teacher's ID
        )

        db.session.add(new_class)
        db.session.commit()
        flash('New class added successfully!', 'success')
        return redirect(url_for('teacher_classes'))  # Redirect to the teacher's classes page

    return render_template('add.html')  # Return to the form if GET request

@app.route('/teacher_classes')
@login_required  # Ensure only logged-in teachers can access this
def teacher_classes():
    # Fetch the classes created by the logged-in teacher based on teacher_id
    classes = Tclass.query.filter_by(teacher_id=current_user.id).all()
    return render_template('teacher/myclasses.html', classes=classes)

@app.route('/teacher/class/<int:class_id>', methods=['GET', 'POST'])
def class_details_t(class_id):
    # Fetch the class data from the database
    class_data = Tclass.query.get(class_id)

    if request.method == 'POST':
        # Only allow the teacher of the class to update the Zoom link
        if current_user.id == class_data.teacher_id:
            zoom_link = request.form.get('zoom_link')
            class_data.zoom_link = zoom_link  # Update the Zoom link for the class
            db.session.commit()  # Commit the changes to the database
            return redirect(url_for('class_details_t', class_id=class_id))  # Redirect to the class details page

    return render_template('teacher/class_page.html', class_data=class_data,class_id=class_id)


@app.route('/class/<int:class_id>/add_zoom_link', methods=['POST'])
@csrf.exempt
def add_zoom_link(class_id):
    # Fetch the class based on the class_id
    class_data = Tclass.query.get(class_id)
    
    # Make sure the current user is the teacher
    if current_user.id == class_data.teacher_id:
        # Get the Zoom link from the form
        zoom_link = request.form.get('zoom_link')
        class_data.zoom_link = zoom_link  # Update the Zoom link for the class
        db.session.commit()  # Commit the changes to the database

    return redirect(url_for('class_details_t', class_id=class_id))


@app.route('/class/<int:class_id>/add_quiz', methods=['GET', 'POST'])
@csrf.exempt
def add_quiz_link(class_id):
    # Fetch the class based on the class_id
    class_data = Tclass.query.get(class_id)

    if request.method == 'POST':
        # Ensure the current user is the teacher
        if current_user.id == class_data.teacher_id:
            # Get the quiz link from the form
            quiz_link = request.form.get('quiz_link')
            class_data.quiz_link = quiz_link  # Update the quiz link for the class
            db.session.commit()  # Commit the changes to the database
        
        # After adding the quiz link, redirect to the class details page
        return redirect(url_for('class_details_t', class_id=class_id))
        
    return render_template('teacher/add_quiz_link.html', class_id=class_id, class_data=class_data)

@app.route('/class/<int:class_id>/add_exam', methods=['GET', 'POST'])
@csrf.exempt
def add_exam_link(class_id):
    # Fetch the class based on the class_id
    class_data = Tclass.query.get(class_id)

    if request.method == 'POST':
        # Ensure the current user is the teacher
        if current_user.id == class_data.teacher_id:
            # Get the exam link from the form
            exam_link = request.form.get('exam_link')
            class_data.exam_link = exam_link  # Update the exam link for the class
            db.session.commit()  # Commit the changes to the database
        
        # After adding the exam link, redirect to the class details page
        return redirect(url_for('class_details_t', class_id=class_id))
        
    return render_template('teacher/add_exam_link.html', class_id=class_id, class_data=class_data)
@app.route('/upload_attendance/<int:class_id>', methods=['GET', 'POST'])
@csrf.exempt
def upload_attendance(class_id):
    if request.method == 'POST':
        if 'file' not in request.files:
          flash('no file in request')
          return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = os.path.join(app.config['UPLOADED_IMAGES_DEST'],file.filename)
            file.save(filename)
            get_attendance(filename)
            flash('Attendance processed successfully!','success')
            return redirect(url_for('class_details_t',class_id = class_id))
          
    return render_template('upload_attendance.html',class_id=class_id)

import csv

import csv

import csv

def get_attendance(filename):
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        print("CSV Headers:", reader.fieldnames)  # Print out the headers
        zoom_attendance = {row['Zoom ID']: row for row in reader}
        
        users = User.query.all()  # This returns a list of User objects
        
        # Iterate over each user to check if they missed a class
        for user in users:
            # Strip the `id` from the CSV if it exists (if present as part of the name)
            combined_name = f'{user.first_name} {user.last_name}'

            # Strip the ID from the CSV names (if it's in the CSV) for comparison
            for zoom_id, row in zoom_attendance.items():
                csv_name = row['Name'].strip()  # Assuming the name is in the 'Name' field in the CSV
                csv_name_parts = csv_name.split()
                if len(csv_name_parts) > 2:  # ID may be at the end
                    csv_name = ' '.join(csv_name_parts[:-1])  # Remove the last part (ID)
                
                # Now compare the name without the ID
                if csv_name == combined_name:
                    break
            else:
                # If the user name isn't found in the CSV, mark them as missing the class
                user.missed_classes += 1
                db.session.commit()

                
@app.route('/check_missed_classes', methods=['GET'])
def check_missed_classes():
    # Fetch students who have missed more than 3 classes
    students = User.query.filter(User.missed_classes > 3).all()
    
    # Send reminder email for each student
    for student in students:
        # Pass necessary details to send_reminder_email
        send_reminder_email(
            user_email=student.email, 
            first_name=student.first_name, 
            last_name=student.last_name, 
            missed_classes=student.missed_classes
        )
    
    return "Reminders sent!", 200





















































@app.route('/static/js/OneSignalSDKWorker.js')
def onesignal_worker():
    directory = os.path.join(app.root_path, 'static/js')
    return send_from_directory(directory, 'OneSignalSDKWorker.js')
        

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0',debug=True)