import os
import re
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, emit
from flask_mail import Mail, Message as MailMsg
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import request, redirect, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:281125@localhost/CTKapp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db = SQLAlchemy(app)
socketio = SocketIO(app)
mail = Mail(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), unique=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    phone = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(128))
    name = db.Column(db.String(80))
    contact = db.Column(db.String(80))
    avatar = db.Column(db.String(200), default="/static/images/default-user.png")
    theme = db.Column(db.String(10), default="light")
    is_admin = db.Column(db.Boolean, default=False)
    rooms = db.relationship("RoomMember", backref="user", lazy=True)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(8), unique=True, nullable=False)
    name = db.Column(db.String(80))
    icon = db.Column(db.String(200), default="/static/images/default-room.png")
    wallpaper = db.Column(db.String(200), default="")
    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    messages = db.relationship("Message", backref="room", lazy=True)
    members = db.relationship("RoomMember", backref="room", lazy=True)

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    room_id = db.Column(db.Integer, db.ForeignKey("room.id"))
    last_opened = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.Enum('pending', 'approved', 'rejected'), default='pending')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("room.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    content = db.Column(db.Text)
    file_url = db.Column(db.String(200))
    file_type = db.Column(db.String(20))
    is_broadcast = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    type = db.Column(db.Enum('join_request','admin_msg','approval','broadcast'))
    room_id = db.Column(db.Integer, db.ForeignKey("room.id"))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- Utility ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png','jpg','jpeg','gif','pdf','docx','mp3','mp4'}

def password_strength(password):
    if (len(password) >= 8 and
        re.search(r'\d', password) and
        re.search(r'[A-Za-z]', password) and
        re.search(r'[!@$%^&*()]', password) and
        not re.search(r'[#\.\-]', password)):
        return True
    return False

def unique_user_fields(username, email, phone, user_id):
    return not (User.query.filter((User.username==username)|(User.email==email)|(User.phone==phone)|(User.user_id==user_id)).first())






'''
@app.route('/toggle_theme')
def toggle_theme():
    current = session.get('theme', 'light')
    session['theme'] = 'dark' if current == 'light' else 'light'
    return redirect(request.args.get('next') or url_for('home'))
'''

@app.route('/toggle_theme')
def toggle_theme():
    current = session.get('theme', 'light')
    session['theme'] = 'dark' if current == 'light' else 'light'
    return redirect(request.args.get('next') or url_for('home'))


# --- Registration ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        user_id = username + '@CTKVoila'
        if (len(username) < 8 or not re.search(r'\d', username)):
            flash("Username must be 8 chars and contain a number.")
            return render_template('register.html')
        if not password_strength(password):
            flash("Password must be 8+ chars, contain a number, a special symbol (not # . -), and a letter.")
            return render_template('register.html')
        if not unique_user_fields(username, email, phone, user_id):
            flash("Username, email, phone, or userId already taken.")
            return render_template('register.html')
        if password == username or password == email or password == user_id or password == name:
            flash("Password cannot be same as username, email, userId, or name.")
            return render_template('register.html')
        hashed_pw = generate_password_hash(password)
        user = User(name=name, username=username, email=email, phone=phone, password=hashed_pw, user_id=user_id, is_admin=(User.query.count()==0))
        db.session.add(user)
        db.session.commit()
        flash("Registered! Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

# --- Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            session['theme'] = user.theme
            return redirect(url_for('home'))
        flash("Invalid credentials.")
    return render_template('admin_login.html')

# --- Forgot Password ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(16)
            # Store token in session or DB (not shown here)
            msg = MailMsg('CTKapp Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Hi {user.name},\n\nTo reset your password, click: http://localhost:5000/reset_password/{token}"
            mail.send(msg)
            flash("Password reset email sent.")
            return redirect(url_for('login'))
        flash("Email not found.")
    return render_template('forgot_password.html')

@app.route('/preview/')
def preview():
	return render_template("preview.html")

@app.route("/", methods=["GET", "POST"])
def home():
    user = User.query.get(session.get('user_id'))
    if not user:
        return redirect(url_for("login"))

    # Handle join/create room
    error = None
    if request.method == "POST":
        if "create" in request.form:
            code = secrets.token_hex(4)
            room = Room(code=code, name="New Room", creator_id=user.id)
            db.session.add(room)
            db.session.commit()
            # Creator is auto-approved
            db.session.add(RoomMember(user_id=user.id, room_id=room.id, status='approved'))
            db.session.commit()
            return redirect(url_for("room", code=code))
        elif "join" in request.form:
            code = request.form.get("code")
            room = Room.query.filter_by(code=code).first()
            if not room:
                error = "Room not found"
            else:
                # Check if already a member
                member = RoomMember.query.filter_by(user_id=user.id, room_id=room.id).first()
                if member:
                    if member.status == 'approved':
                        return redirect(url_for("room", code=code))
                    elif member.status == 'pending':
                        error = "Your join request is pending approval."
                    elif member.status == 'rejected':
                        error = "Your join request was rejected."
                else:
                    # Create join request (pending)
                    db.session.add(RoomMember(user_id=user.id, room_id=room.id, status='pending'))
                    db.session.add(Notification(
                        user_id=room.creator_id,
                        message=f"{user.name} requested to join room {room.name}.",
                        type='join_request',
                        room_id=room.id
                    ))
                    db.session.commit()
                    error = "Join request sent. Wait for admin approval."

    # Approved rooms for sidebar
    approved_rooms = RoomMember.query.filter_by(user_id=user.id, status='approved').order_by(RoomMember.last_opened.desc()).all()
    # Notifications for this user
    notifications = Notification.query.filter_by(user_id=user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    # Pending join requests if admin
    join_requests = []
    if user.is_admin:
        join_requests = RoomMember.query.filter_by(status='pending').all()

    return render_template(
        "home.html",
        user=user,
        rooms=approved_rooms,
        notifications=notifications,
        join_requests=join_requests,
        error=error
    )

# --- Profile ---
@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = User.query.get(session.get('user_id'))
    if not user:
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form.get("name")
        contact = request.form.get("contact")
        avatar_file = request.files.get("avatar_file")
        if avatar_file and allowed_file(avatar_file.filename):
            filename = secure_filename(f"{datetime.utcnow().timestamp()}_{avatar_file.filename}")
            avatar_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.avatar = f"/static/uploads/{filename}"
        user.name = name
        user.contact = contact
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("profile.html", user=user)

@app.route('/approve_join/<int:request_id>', methods=['POST'])
def approve_join(request_id):
    user = User.query.get(session.get('user_id'))
    if not user or not user.is_admin:
        return "Unauthorized", 403
    join_req = RoomMember.query.get_or_404(request_id)
    action = 'approve' if 'approve' in request.form else 'reject'
    join_req.status = 'approved' if action == 'approve' else 'rejected'
    db.session.commit()
    # Notify the user
    db.session.add(Notification(
        user_id=join_req.user_id,
        message=f"Your join request for {join_req.room.name} was {join_req.status}.",
        type='approval',
        room_id=join_req.room_id
    ))
    db.session.commit()
    return redirect(url_for('home'))


# --- Room/Chat ---
@app.route("/room/<code>", methods=["GET", "POST"])
def room(code):
    user = User.query.get(session.get('user_id'))
    room = Room.query.filter_by(code=code).first_or_404()
    member = RoomMember.query.filter_by(user_id=user.id, room_id=room.id).first()
    if not member or member.status != 'approved':
        # If not approved, show request to join
        return render_template("room.html", user=user, room=room, code=code, messages=[], is_creator=False, members=[], join_request=True)
    # Show chat, handle file upload, sticky input, scroll, etc.
    messages = Message.query.filter_by(room_id=room.id).order_by(Message.timestamp).all()
    is_creator = (user.id == room.creator_id)
    members = [m.user for m in room.members if m.status == 'approved']
    return render_template("room.html", user=user, room=room, code=code, messages=messages, is_creator=is_creator, members=members, join_request=False)

@app.route("/edit_room/<code>", methods=["POST"])
def edit_room(code):
    user = User.query.get(session.get('user_id'))
    room = Room.query.filter_by(code=code).first_or_404()
    if user.id != room.creator_id:
        return "Unauthorized", 403
    # Get new data from form
    room.name = request.form.get("name")
    icon_file = request.files.get("icon_file")
    wallpaper_file = request.files.get("wallpaper_file")
    if icon_file and allowed_file(icon_file.filename):
        filename = secure_filename(f"{datetime.utcnow().timestamp()}_{icon_file.filename}")
        icon_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        room.icon = f"/static/uploads/{filename}"
    if wallpaper_file and allowed_file(wallpaper_file.filename):
        filename = secure_filename(f"{datetime.utcnow().timestamp()}_{wallpaper_file.filename}")
        wallpaper_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        room.wallpaper = f"/static/uploads/{filename}"
    db.session.commit()
    return redirect(url_for("room", code=code))


# --- Error route ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# --- File Upload/Sharing ---
@app.route('/upload', methods=['POST'])
def upload():
    user = User.query.get(session.get('user_id'))
    room_code = request.form.get('room_code')
    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400
    filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    url = f"/static/uploads/{filename}"
    file_type = file.filename.rsplit('.', 1)[1].lower()
    room = Room.query.filter_by(code=room_code).first()
    msg = Message(room_id=room.id, user_id=user.id, file_url=url, file_type=file_type, timestamp=datetime.utcnow())
    db.session.add(msg)
    db.session.commit()
    socketio.emit("message", {
        "message": "",
        "sender": user.name,
        "avatar": user.avatar,
        "timestamp": msg.timestamp.strftime("%H:%M"),
        "file_url": url,
        "file_type": file_type
    }, to=room_code)
    return jsonify({'url': url, 'type': file_type})

# --- SocketIO events for chat, join requests, etc. ---
@socketio.on("join")
def on_join(data):
    code = data["room"]
    user = User.query.get(session.get('user_id'))
    join_room(code)
    room = Room.query.filter_by(code=code).first()
    member = RoomMember.query.filter_by(user_id=user.id, room_id=room.id).first()
    if not member or member.status != 'approved':
        emit("message", {
            "message": "You are not approved to join this room.",
            "sender": "",
            "avatar": "",
            "timestamp": datetime.now().strftime("%H:%M")
        }, to=code)
        return
    emit("message", {
        "message": f"{user.name} joined the room.",
        "sender": "",
        "avatar": "",
        "timestamp": datetime.now().strftime("%H:%M")
    }, to=code)

@socketio.on("message")
def handle_message(data):
    code = data["room"]
    user = User.query.get(session.get('user_id'))
    room = Room.query.filter_by(code=code).first()
    msg = Message(room_id=room.id, user_id=user.id, content=data["message"], timestamp=datetime.utcnow())
    db.session.add(msg)
    db.session.commit()
    emit("message", {
        "message": data["message"],
        "sender": user.name,
        "avatar": user.avatar,
        "timestamp": msg.timestamp.strftime("%H:%M"),
        "file_url": "",
        "file_type": ""
    }, to=code)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
