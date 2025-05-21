from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file, jsonify
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
    avatar = db.Column(db.LargeBinary(length=(2**32)-1), nullable=True)
    # relacije sa cascade delete
    posts = db.relationship('Post', back_populates='user', cascade='all, delete-orphan', lazy=True)
    comments = db.relationship('Comment', back_populates='user', cascade='all, delete-orphan', lazy=True)
    likes = db.relationship('Like', back_populates='user', cascade='all, delete-orphan', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
# --- Model za objave ---

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    photo = db.Column(db.LargeBinary(length=(2**32)-1), nullable=False)  # Smjestava slike u binarnom formatu u db
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
    # Relacije
    user = db.relationship('User', back_populates='likes')
    post = db.relationship('Post', back_populates='likes')

# Kreiranje tabela
with app.app_context():
    db.create_all()
    # Provjera da li postoji admin nalog
    if not User.query.filter((User.username == 'admin') | (User.email == 'admin@memento.com')).first():
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
            flash(f'Welcome, {user.username}!', 'success')
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
    if 'user_id' not in session:
        flash('You must be logged in to view a profile.', 'error')
        return redirect(url_for('login'))
    viewed_user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=viewed_user.id).order_by(Post.date_posted.desc()).all()
    
    is_own_profile = 'user_id' in session and session['user_id'] == viewed_user.id
    
    return render_template('profile.html',
                         viewed_user=viewed_user,
                         posts=posts,
                         is_own_profile=is_own_profile)

# ruta za upload
@app.route('/upload', methods=['GET', 'POST'])
def upload_photo():
    user_id = session.get('user_id') 
    if 'user_id' not in session:
        flash('You must be logged in to upload a photo.', 'error')
        return redirect(url_for('login'))
    if not user_id:
        flash('You must be logged in to upload a photo.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST' and 'photo' in request.files:
        photo = request.files['photo']

        # Validacija tipa fajla
        if photo.mimetype not in ['image/png', 'image/jpeg']:
            flash('Only PNG and JPEG files are allowed.', 'error')
            return redirect(url_for('upload_photo'))

        # Citaj fajl i sacuvaj ga u bazi
        photo_data = photo.read()
        caption = request.form.get('caption')

        # sacuvaj post u bazi
        new_post = Post(photo=photo_data, caption=caption, user_id=user_id)
        db.session.add(new_post)
        db.session.commit()

        flash('Photo uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/photo/<int:post_id>')
def get_photo(post_id):
    if 'user_id' not in session:
        flash('You must be logged in to edit a profile.', 'error')
        return redirect(url_for('login'))
    post = Post.query.get_or_404(post_id)
    return send_file(BytesIO(post.photo), mimetype='image/jpeg')

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        flash('You must be logged in to delete a post.', 'error')
        return redirect(url_for('login'))

    post = Post.query.get_or_404(post_id)

    # Provjera da li je korisnik vlasnik posta ili admin
    if post.user_id != session['user_id'] and session.get('role') != 'admin':
        flash('You are not authorized to delete this post.', 'error')
        return redirect(url_for('dashboard'))

    # Brisanje posta
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully!', 'success')

    # Ako je post obrisan sa profila, redirektuj na profil
    from_profile = request.form.get('from_profile')
    if from_profile:
        return redirect(url_for('user_profile', username=from_profile))
    return redirect(url_for('dashboard'))

#ruta za like
@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        return jsonify({'error': 'You must be logged in to like a post.'}), 401

    user_id = session['user_id']
    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    liked = False

    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
    else:
        new_like = Like(user_id=user_id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
        liked = True

    return jsonify({'liked': liked, 'likes_count': len(post.likes)})

# ruta za upload avatara
@app.route('/upload_avatar', methods=['GET', 'POST'])
def upload_avatar():
    if 'user_id' not in session:
        flash('You must be logged in to upload an avatar.', 'error')
        return redirect(url_for('login'))

    user = User.query.get_or_404(session['user_id'])

    if request.method == 'POST' and 'avatar' in request.files:
        avatar = request.files['avatar']

        # Validacija tipa fajla
        if avatar.mimetype not in ['image/png', 'image/jpeg']:
            flash('Only PNG and JPEG files are allowed.', 'error')
            return redirect(url_for('upload_avatar'))

        # Cuvanje avatara u bazi
        user.avatar = avatar.read()
        db.session.commit()
        flash('Avatar uploaded successfully!', 'success')
        return redirect(url_for('user_profile', username=user.username))

    return render_template('upload_avatar.html')
    
# uzima avatar iz baze
@app.route('/avatar/<int:user_id>')
def get_avatar(user_id):
    if 'user_id' not in session:
        flash('You must be logged in to change an avatar.', 'error')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    if user.avatar:
        return send_file(BytesIO(user.avatar), mimetype='image/jpeg')
    else:
        return send_file('static/images/empty.png', mimetype='image/png')

#ruta za edit profile
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('You must be logged in to edit a profile.', 'error')
        return redirect(url_for('login'))

    edit_user_id = request.args.get('user_id', type=int)
    if session.get('role') == 'admin' and edit_user_id:
        user = User.query.get_or_404(edit_user_id)
    else:
        user = User.query.get_or_404(session['user_id'])

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        avatar = request.files['avatar'] if 'avatar' in request.files else None

        # Provera da li je username ili email već zauzet (osim za trenutnog usera)
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Username is already taken. Please choose another.', 'error')
            return redirect(url_for('edit_profile', user_id=user.id if session.get('role') == 'admin' else None))

        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email is already in use. Please choose another.', 'error')
            return redirect(url_for('edit_profile', user_id=user.id if session.get('role') == 'admin' else None))

        user.username = username
        user.email = email
        if password:
            user.set_password(password)
        if avatar and avatar.mimetype in ['image/png', 'image/jpeg']:
            user.avatar = avatar.read()

        db.session.commit()

        # Ako admin menja tuđi profil, ne menja svoju sesiju
        if session.get('role') != 'admin' or user.id == session['user_id']:
            session['username'] = user.username

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile', username=user.username))

    return render_template('edit_profile.html', user=user)

@app.route('/comments/<int:post_id>', methods=['GET', 'POST'])
def comments_page(post_id):
    if 'user_id' not in session:
        flash('You must be logged in to comment a profile.', 'error')
        return redirect(url_for('login'))
    post = Post.query.get_or_404(post_id)
    user = User.query.get(session['user_id']) if 'user_id' in session else None

    if request.method == 'POST':
        if not user:
            flash('You must be logged in to comment.', 'error')
            return redirect(url_for('login'))
        text = request.form.get('comment')
        if text:
            new_comment = Comment(text=text, user_id=user.id, post_id=post.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added!', 'success')
            return redirect(url_for('comments_page', post_id=post.id))

    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.date_posted.desc()).all()
    return render_template('comments_page.html', post=post, comments=comments)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        flash('You must be logged in to edit a profile.', 'error')
        return redirect(url_for('login'))
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id
    if 'user_id' not in session or (comment.user_id != session['user_id'] and session.get('role') != 'admin'):
        flash('You are not authorized to delete this comment.', 'error')
        return redirect(url_for('comments_page', post_id=post_id))
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted.', 'success')
    return redirect(url_for('comments_page', post_id=post_id))

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('You are not authorized to access the admin panel.', 'error')
        return redirect(url_for('dashboard'))

    users = User.query.all()

    return render_template('admin_panel.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('You are not authorized to delete users.', 'error')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)

    # prevencija da admin obrise samog sebe
    if user.id == session['user_id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_panel'))

    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} has been deleted.', 'success')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True)