import os

import gnupg
from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, session, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from . import db, login_manager
from .forms import (ChangePasswordForm, ChangeRoleForm, LoginForm, ProfileForm,
                    SearchForm, SignUpForm)
from .models import Message, users

main = Blueprint('main', __name__)

gpg_home = ("./gnupg_home")
os.makedirs(gpg_home, exist_ok=True)
gpg = gnupg.GPG(gnupghome=gpg_home)


@main.route('/')
def home():
    return render_template('home.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        print(">> Login button Clicked <<")
        if form.validate_on_submit():
            print(">> Login validate Clicked <<")
            username = request.form.get('username')
            password = request.form.get('password')

            # Check if user exists
            user = users.query.filter_by(username=username).first()
            print("User: ", user)
            if user is None:
                flash('Username is not valid.', category='danger')
            elif not check_password_hash(user.password, password):
                flash('Password is not valid.', category='danger')
            else:
                login_user(user)
                # Create session
                session['user'] = username
                session['is_logged_in'] = True
                session['is_authenticated'] = True
                # Flash welcome message
                flash(f'Welcome back ! {
                      user.display_name}', category='success')
                return redirect(url_for('main.home'))

    return render_template('login.html', form=form)


@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()  # Create an instance of the SignUpForm

    if form.validate_on_submit():  # Check if the form is submitted and valid
        username = form.username.data
        display_name = form.display_name.data
        email = form.email.data
        password = form.password.data

        # Basic validation
        if users.query.filter_by(email=email).first():
            flash('Email is already registered.', category='danger')
        elif users.query.filter_by(username=username).first():
            flash('Username is already taken.', category='danger')
        else:
            # Create user
            hashed_password = generate_password_hash(
                password, method='scrypt', salt_length=8)
            # Generating the PGP Keypair
            input_data = gpg.gen_key_input(
                name_email=email,
                name_real=username,
                passphrase=hashed_password,
                key_type="RSA",
                key_length=4096
            )
            key = gpg.gen_key(input_data)
            new_user = users(
                username=username.lower(),
                display_name=display_name,
                email=email,
                public_key=gpg.export_keys(key.fingerprint),
                private_key=gpg.export_keys(
                    key.fingerprint, True, passphrase=hashed_password),
                password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash(message='Account created successfully!', category='success')
            return redirect(url_for('main.login'))

    return render_template('signup.html', title="Sign Up", form=form)


@main.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('Logout successful!', category='success')
    return redirect(url_for('main.login'))


@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    user = current_user

    if request.method == 'POST':
        # Update user attributes
        user.username = form.username.data
        user.display_name = form.display_name.data
        user.email = form.email.data
        user.bio = form.bio.data

        # Handle profile picture upload
        if form.avatar.data:
            avatar_file = form.avatar.data
            avatar_filename = secure_filename(avatar_file.filename)

            # Check file size
            # Move cursor to the end of the file
            avatar_file.seek(0, os.SEEK_END)
            file_size = avatar_file.tell()    # Get file size in bytes
            avatar_file.seek(0)              # Reset file pointer to the start

            # 2MB limit (2 * 1024 * 1024 bytes)
            if file_size > 2 * 1024 * 1024:
                flash('File size must be less than or equal to 2MB.',
                      category='error')
                return redirect(url_for('main.profile'))

            # Save the file
            avatar_file.save(os.path.join(current_app.root_path,
                             'static/profile_pics', avatar_filename))
            user.image_file = avatar_filename

        db.session.commit()
        flash('Profile updated successfully!', category='success')
        return redirect(url_for('main.profile'))

    # Pre-fill form with current user data
    form.avatar.data = user.image_file
    form.username.data = user.username
    form.display_name.data = user.display_name
    form.email.data = user.email
    form.bio.data = user.bio
    return render_template('profile.html', form=form, user=user)


@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))


@main.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    users_db = users.query.all()
    password_form = ChangePasswordForm()
    role_form = ChangeRoleForm()
    search_form = SearchForm()
    results = None
    if search_form.validate_on_submit():
        search_query = search_form.query.data  # Get the search input
        # Query the database to find matching users
        results = users.query.filter(
            users.username.like(f'%{search_query}%')).all()
        # Redirect or render the template with results
        return render_template('search_results.html', results=results, users=users_db, form=search_form, passwordForm=password_form, roleForm=role_form)
    return render_template('admin_dashboard.html', users_db=users_db, passwordForm=password_form, roleForm=role_form, searchForm=search_form, results=results)
    users = users.query.all()


@main.route('/change_password/<int:id>', methods=['POST'])
@login_required
def change_password(id):
    print(f"Change password route invoked for user {id}")
    user = users.query.get_or_404(id)
    print(f"User: {user}")
    form = ChangePasswordForm(request.form)  # Bind request data
    if request.form.get('new_password'):
        print("Form validated")
        if form.new_password.data != form.confirm_password.data:
            print("New passwords do not match")
            flash('New passwords do not match.', category='danger')
        else:
            print("Updating password")
            user.password = generate_password_hash(
                form.new_password.data, method='scrypt', salt_length=8)
            db.session.commit()
            flash(f'{user.display_name} Password changed successfully!',
                  category='success')
            return redirect(url_for('main.admin_dashboard'))
    return render_template('admin_dashboard.html', passwordForm=form, user=user)


@main.route('/change_role/<int:id>', methods=['POST'])
@login_required
def change_role(id):
    print(f"Change role route invoked for user {id}")
    user = users.query.get_or_404(id)
    print(f"User: {user}")
    form = ChangeRoleForm(request.form)
    if request.form.get('new_role'):
        print("Form validated")
        user.role = form.new_role.data
        db.session.commit()
        flash(f'{user.display_name} Role changed successfully!',
              category='success')
        return redirect(url_for('main.admin_dashboard'))
    return render_template('admin_dashboard.html', roleForm=form, user=user)


@main.route('/delete_user/<int:id>', methods=['POST', 'GET'])
@login_required
def delete_user(id):
    user = users.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash(f'{user.display_name} deleted successfully!', category='success')
    return redirect(url_for('main.admin_dashboard'))


@main.route("/<int:id>/inbox", methods=["POST", "GET"])
@login_required
def show_inbox(id):
    received_messages = Message.query.filter_by(recipient_id=id).all()
    users_db = users.query.all()

    return render_template("inbox.html", users=users_db, messages=received_messages)


@main.route("/send_message", methods=["POST", "GET"])
@login_required
def send_message():
    if request.method == "POST":
        recipient_id = request.form.get("recipient_id")
        recipient = users.query.get(recipient_id)
        plaintext_message = request.form.get("message")

        if not recipient or not plaintext_message:
            flash("Recipient and message are required.", "danger")
            return redirect(url_for("main.send_message"))
        public_key = recipient.public_key

        if not public_key:
            flash("Recipient does not have a public key.", "danger")
            return redirect(url_for("main.send_message"))

        gpg.import_keys(public_key)

        # Encrypt the message
        encrypted_data = gpg.encrypt(
            plaintext_message, recipients=[recipient.email], always_trust=True)

        if not encrypted_data.ok:
            flash("Encryption Failed: "+encrypted_data.status, "danger")
            return redirect(url_for("main.send_message"))

        # Save the encrypted message to the database
        new_message = Message(
            sender_id=current_user.id,
            recipient_id=recipient.id,
            body=str(encrypted_data),
        )
        db.session.add(new_message)
        db.session.commit()

        flash("Message sent successfully!", "success")
        return redirect(url_for("main.show_inbox", id=current_user.id))
    # For GET request, show the send message form
    all_users = users.query.all()
    return render_template("send_message.html", users=all_users)


@main.route('/view_message/<int:id>', methods=["GET", "POST"])
@login_required
def view_message(id):
    message = Message.query.get_or_404(id)

    # Check if the current user is the recipient or the sender
    if message.recipient_id != current_user.id:
        flash("You are not authorized to view this message.", "danger")
        return redirect(url_for('main.inbox'))

    decrypted_message = None

    if request.method == "POST":
        # Retrieve the user's password (which is the passphrase for the private key)
        user_password = current_user.password

        # Decrypt the message using the user's private key and password
        private_key = current_user.private_key
        passphrase = user_password  # Use the user's password as the passphrase

        # Decrypt the encrypted message using the private key and passphrase
        decrypted_data = gpg.decrypt(message.body, passphrase=passphrase)

        if decrypted_data.ok:
            decrypted_message = decrypted_data.data.decode('utf-8')
        else:
            flash("Decryption failed: " + decrypted_data.status, "danger")
            return redirect(url_for('main.view_message', id=id))

    return render_template('view_message.html', message=message, decrypted_message=decrypted_message)


def decrypt_with_private_key(body, private_key):
    # Use the private key and decrypt the message
    gpg = gnupg.GPG(gnupghome='./gnupg_home')
    gpg.import_keys(private_key)
    decrypted_data = gpg.decrypt(body, passphrase=private_key)

    if decrypted_data.ok:
        return str(decrypted_data)
    else:
        return None
