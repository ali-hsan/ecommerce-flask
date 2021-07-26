from flask import Flask, render_template, request, flash, redirect, abort
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import UnmappedInstanceError
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap
from forms import create_product_form, RegisterForm, LoginForm, create_product_edit_form
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_migrate import Migrate
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///store_db.db').replace("://"
                                                                                                           , "ql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Bootstrap(app)
CKEditor(app)

login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created = db.Column(db.DateTime(), default=db.func.now())
    items = db.relationship('CartItem', back_populates='user')

    def __repr__(self):
        return f'User{self.id}: {self.name}'


class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    products = db.relationship('Product', back_populates='category')
    created = db.Column(db.DateTime(), default=db.func.now())
    updated = db.Column(db.DateTime(), default=db.func.now(), onupdate=db.func.now())

    def __repr__(self):
        return f'Category{self.id}: {self.name}'


class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text(), nullable=False)
    images = db.Column(db.Text(), nullable=False)
    regular_price = db.Column(db.Float(), default=0)
    discount_price = db.Column(db.Float(), default=0)
    quantity = db.Column(db.Integer(), default=0)
    on_sale = db.Column(db.Boolean(), default=False)
    category = db.relationship('Category', back_populates='products')
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    created = db.Column(db.DateTime(), default=db.func.now())
    updated = db.Column(db.DateTime(), default=db.func.now(), onupdate=db.func.now())

    def __repr__(self):
        return f'Product{self.id}: {self.name}'


class CartItem(db.Model):
    __tablename__ = 'cartitem'
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, nullable=False)
    size = db.Column(db.String(255), nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', back_populates='items')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If logged in and If id is not 1 then return abort with 403 error
        if not current_user.is_anonymous and current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# Check if current user id admin or not
def is_admin():
    if current_user.is_anonymous:
        return False
    elif current_user.id != 1:
        return False
    else:
        return True


# if unauthorized, forbidden or page not found return 404.html
@app.errorhandler(404)
def page_not_found(e):
    categories = Category.query.all()
    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    return render_template('404.html', categories=categories, total_items=total_items), 404


@app.errorhandler(401)
def unauthorized(e):
    categories = Category.query.all()
    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    return render_template('404.html', categories=categories, total_items=total_items), 401


@app.errorhandler(403)
def forbidden(e):
    categories = Category.query.all()
    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    return render_template('404.html', categories=categories, total_items=total_items), 403


@app.route('/')
def index():
    categories = Category.query.all()
    for category in categories:
        if not category.products:
            db.session.delete(Category.query.get(category.id))
            db.session.commit()

    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)

    return render_template('index.html', categories=categories, is_admin=is_admin(),
                           is_anonymous=current_user.is_authenticated, total_items=total_items)


@app.route('/product/<int:product_id>')
def product_page(product_id):
    product = Product.query.get(product_id)
    if product is None:
        return abort(404)

    categories = Category.query.all()
    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    return render_template('product_page.html', product=product, categories=categories,
                           is_anonymous=current_user.is_authenticated, total_items=total_items)


def flash_errors(form):
    """Flashes form errors"""
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ), 'error')


@app.route('/add_item', methods=['GET', 'POST'])
@login_required
@admin_only
def add_item():
    categories = Category.query.all()
    choices = [(category.id, category.name) for category in categories]
    choices.insert(0, (None, None))
    form = create_product_form(choices)
    if request.method == 'POST' and form.validate():
        category = Category.query.get(form.category.data)
        if category is None:
            try:
                db.session.add(Category(name=form.create_category.data))
                db.session.commit()
                category = Category.query.filter_by(name=form.create_category.data).first()
            except IntegrityError:
                db.session.rollback()
                flash('Category already exists.')

        product = Product(
            name=form.name.data,
            description=form.description.data,
            images=form.images.data,
            regular_price=form.price.data,
            discount_price=form.discount_price.data,
            quantity=form.quantity.data,
            on_sale=form.on_sale.data,
            category=category,
            created=datetime.now(),
            updated=datetime.now()
        )
        try:
            db.session.add(product)
            db.session.commit()
            return redirect('/')
        except IntegrityError:
            db.session.rollback()
            flash('Product is already in database.')
    else:
        flash_errors(form)

    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    return render_template('add_item.html', form=form, categories=categories,
                           is_anonymous=current_user.is_authenticated, total_items=total_items)


@app.route('/edit_item/<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_only
def edit_item(product_id):
    try:
        to_edit = Product.query.get(product_id)
        form = create_product_edit_form(to_edit)
        if request.method == 'POST' and form.validate():
            to_edit.name = form.name.data
            to_edit.description = form.description.data
            to_edit.images = form.images.data
            to_edit.regular_price = form.price.data
            to_edit.discount_price = form.discount_price.data
            to_edit.quantity = form.quantity.data
            to_edit.on_sale = form.on_sale.data
            to_edit.updated = datetime.now()
            db.session.commit()
            return redirect('/')
        else:
            flash_errors(form)
        categories = Category.query.all()
        total_items = 0
        if current_user.is_authenticated:
            total_items = len(current_user.items)
        return render_template('edit_item.html', form=form, to_edit=to_edit, categories=categories,
                               is_anonymous=current_user.is_authenticated, total_items=total_items)

    except AttributeError:
        abort(404)


@app.route('/editcatename/<int:category_id>/<name>', methods=['GET', 'POST'])
@login_required
@admin_only
def edit_category_name(category_id, name):
    to_edit = Category.query.get(category_id)
    to_edit.name = name
    db.session.commit()
    return redirect('/')


@app.route("/delete/<int:product_id>")
@login_required
@admin_only
def delete_product(product_id):
    to_delete = Product.query.get(product_id)
    db.session.delete(to_delete)
    db.session.commit()
    return redirect('/')


@app.route("/deleteall/<int:category_id>")
@login_required
@admin_only
def delete_all(category_id):
    category = Category.query.get(category_id)
    for product in category.products:
        db.session.delete(product)
        db.session.commit()
        return redirect('/')


@app.route('/category/<int:category_id>')
def view_all(category_id):
    categories = Category.query.all()
    category = Category.query.get(category_id)
    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    return render_template('view_all.html', category=category, is_admin=is_admin(), categories=categories,
                           is_anonymous=current_user.is_authenticated, total_items=total_items)


# Cart
@app.route('/addtocart/<int:product_id>', methods=['GET', 'POST'])
def add_to_cart(product_id):
    if request.method == 'POST' and not current_user.is_authenticated:
        return redirect('/login')
    elif request.method == 'POST':
        card_item = CartItem(
            quantity=request.form.get('quantity'),
            size=request.form.get('size'),
            product_id=product_id,
            user=current_user,
        )
        db.session.add(card_item)
        db.session.commit()
        return redirect('/cart')


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    cart_items = current_user.items
    products = [Product.query.get(item.product_id) for item in cart_items]

    sub_total = 0
    for i in range(len(cart_items)):
        if products[i].discount_price != 0.0:
            sub_total += products[i].discount_price * cart_items[i].quantity
        else:
            sub_total += products[i].regular_price * cart_items[i].quantity

    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    categories = Category.query.all()
    return render_template('cart.html', cart_items=cart_items, products=products, sub_total=int(sub_total),
                           is_anonymous=current_user.is_authenticated, total_items=total_items, categories=categories)


@app.route("/deletecartitem/<int:cart_item_id>")
def delete_cart_item(cart_item_id):
    try:
        to_delete = CartItem.query.get(cart_item_id)
        db.session.delete(to_delete)
        db.session.commit()
    except UnmappedInstanceError:
        pass
    return redirect('/cart')


# Users Handling
@app.route('/signup', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate():
        if User.query.filter_by(email=form.email.data).first():
            # User already exist
            flash("You've already signed up with that email,"
                  " <a href='/login'>Log In</a> instead!")
        else:
            password = form.password.data
            hashed_and_salted_pass = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(name=form.name.data, email=form.email.data, password=hashed_and_salted_pass,
                            created=datetime.now())
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            return redirect('/')
    else:
        flash_errors(form)
    categories = Category.query.all()
    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    return render_template('signup.html', form=form, categories=categories,
                           is_anonymous=current_user.is_authenticated, total_items=total_items)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user is None:
                flash("User not found. <a href='/signup'>Sign Up</a> instead!")
            else:
                hashed_password = user.password
                if check_password_hash(hashed_password, form.password.data):
                    login_user(user)
                    return redirect('/')
                else:
                    flash('Incorrect Password!')
        else:
            flash_errors(form)
    categories = Category.query.all()
    total_items = 0
    if current_user.is_authenticated:
        total_items = len(current_user.items)
    return render_template("login.html", form=form, categories=categories,
                           is_anonymous=current_user.is_authenticated, total_items=total_items)


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')


if __name__ == '__main__':
    app.run()
