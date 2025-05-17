from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/memento_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Model za user ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    avatar = db.Column(db.LargeBinary, nullable=True)  # Store avatar as binary data
    # relacije
    posts = db.relationship('Post', back_populates='user', lazy=True)
    comments = db.relationship('Comment', back_populates='user', lazy=True)
    likes = db.relationship('Like', back_populates='user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
# --- Model za objave ---

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    photo = db.Column(db.LargeBinary, nullable=False)  # Smjestava slike u binarnom formatu u db
    caption = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # relacije
    user = db.relationship('User', back_populates='posts')
    comments = db.relationship('Comment', back_populates='post', cascade='all, delete-orphan')
    likes = db.relationship('Like', back_populates='post', cascade='all, delete-orphan')

# --- Model za komentare ---

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    # relacije
    user = db.relationship('User', back_populates='comments')
    post = db.relationship('Post', back_populates='comments')

# --- Model za lajkove ---

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    # Relationships
    user = db.relationship('User', back_populates='likes')
    post = db.relationship('Post', back_populates='likes')

# Kreiranje tabela
with app.app_context():
    db.create_all()
    # U slucaju da ne postoji admin user, kreiraj ga
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@memento.com', role='admin')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

# --- Rute ---
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        avatar = request.files['avatar'].read() if 'avatar' in request.files else None

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists!', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, avatar=avatar)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('dashboard.html', posts=posts)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/user/<username>')
def user_profile(username):
    viewed_user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=viewed_user.id).order_by(Post.date_posted.desc()).all()
    
    is_own_profile = 'user_id' in session and session['user_id'] == viewed_user.id
    
    return render_template('profile.html',
                         viewed_user=viewed_user,
                         posts=posts,
                         is_own_profile=is_own_profile)

@app.route('/upload', methods=['GET', 'POST'])
def upload_photo():
    user_id = session.get('user_id')  # Uzmi id korisnika iz sesije
    if not user_id:
        flash('You must be logged in to upload a photo.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST' and 'photo' in request.files:
        photo = request.files['photo'].read()
        caption = request.form.get('caption')

        # Cuvanje objave u bazu
        new_post = Post(photo=photo, caption=caption, user_id=user_id)
        db.session.add(new_post)
        db.session.commit()

        flash('Photo uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.route('/photo/<int:post_id>')
def get_photo(post_id):
    post = Post.query.get_or_404(post_id)
    return send_file(BytesIO(post.photo), mimetype='image/jpeg')

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        flash('You must be logged in to delete a post.', 'error')
        return redirect(url_for('login'))

    post = Post.query.get_or_404(post_id)

    # Provjeri ako je trenutni korisnik autor objave
    if post.user_id != session['user_id']:
        flash('You are not authorized to delete this post.', 'error')
        return redirect(url_for('dashboard'))

    # Izbrisi objavu
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        flash('You must be logged in to like a post.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    post = Post.query.get_or_404(post_id)

    # Provjera ako je korisnik vec lajkovao post
    existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()

    if existing_like:
        # ukloni lajk
        db.session.delete(existing_like)
        db.session.commit()
        flash('You unliked the post.', 'info')
    else:
        # lajkuj objavu
        new_like = Like(user_id=user_id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
        flash('You liked the post!', 'success')

    return redirect(url_for('dashboard'))

# ruta za upload avatara
@app.route('/upload_avatar', methods=['GET', 'POST'])
def upload_avatar():
    if 'user_id' not in session:
        flash('You must be logged in to upload an avatar.', 'error')
        return redirect(url_for('login'))

    user = User.query.get_or_404(session['user_id'])

    if request.method == 'POST' and 'avatar' in request.files:
        avatar = request.files['avatar'].read()
        user.avatar = avatar
        db.session.commit()
        flash('Avatar uploaded successfully!', 'success')
        return redirect(url_for('user_profile', username=user.username))

    return render_template('upload_avatar.html')
# uzima avatar iz baze
@app.route('/avatar/<int:user_id>')
def get_avatar(user_id):
    user = User.query.get_or_404(user_id)
    if user.avatar:
        return send_file(BytesIO(user.avatar), mimetype='image/jpeg') 
    else:
        return redirect(url_for('static', filename='images/default_avatar.png'))  # defaultni avatar

if __name__ == '__main__':
    app.run(debug=True)