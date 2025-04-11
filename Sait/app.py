from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "supersecretkey"

db = SQLAlchemy(app)

# Модели базы данных

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Новое поле


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f"<Product {self.name}>"


# Формы

class RegisterForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField("Пароль", validators=[InputRequired(), Length(min=6, max=100)])
    confirm_password = PasswordField("Подтверждение пароля", validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField("Зарегистрироваться")


class LoginForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[InputRequired()])
    password = PasswordField("Пароль", validators=[InputRequired()])
    submit = SubmitField("Войти")


class ProductForm(FlaskForm):
    name = StringField("Название", validators=[InputRequired()])
    description = StringField("Описание", validators=[InputRequired()])
    price = FloatField("Цена", validators=[InputRequired()])
    image_url = StringField("URL изображения", validators=[InputRequired()])
    submit = SubmitField("Добавить товар")

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

    product = db.relationship('Product', backref='cart_items')
    user = db.relationship('User', backref='cart_items')


# Декораторы

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Сначала войдите в систему.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if not user or not user.is_admin:
            flash("Доступ запрещен.", "error")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


# Маршруты

@app.route('/')
def home():
    products = Product.query.limit(5).all()  # или любые товары
    return render_template('home.html', products=products)


@app.route('/catalog')
def catalog():
    products = Product.query.all()
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return render_template('catalog.html', products=products, user=user)


@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash("Вы должны быть авторизованы для просмотра корзины.", "error")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    cart_items = CartItem.query.filter_by(user_id=user.id).all()

    total_price = sum(item.product.price * item.quantity for item in cart_items)

    return render_template('cart.html', cart_items=cart_items, total_price=total_price)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)

        user = User(username=username, password=password, is_admin=False)
        db.session.add(user)
        db.session.commit()
        flash("Регистрация успешна! Теперь войдите в систему.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Добро пожаловать!", "success")
            return redirect(url_for('home'))
        else:
            flash("Неверное имя пользователя или пароль.", "error")

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Вы успешно вышли из системы.", "success")
    return redirect(url_for('home'))


@app.route('/add_product', methods=['GET', 'POST'])
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def add_product(product_id=None):
    form = ProductForm()
    if product_id:
        # Редактируем существующий товар
        product = Product.query.get_or_404(product_id)
        if form.validate_on_submit():
            # Обновляем данные
            product.name = form.name.data
            product.description = form.description.data
            product.price = form.price.data
            product.image_url = form.image_url.data
            db.session.commit()
            flash("Товар успешно обновлен!", "success")
            return redirect(url_for('catalog'))
    else:
        # Добавляем новый товар
        if form.validate_on_submit():
            new_product = Product(
                name=form.name.data,
                description=form.description.data,
                price=form.price.data,
                image_url=form.image_url.data
            )
            db.session.add(new_product)
            db.session.commit()
            flash("Товар успешно добавлен!", "success")
            return redirect(url_for('catalog'))

    return render_template('add_product.html', form=form, product_id=product_id)



@app.route('/delete_product/<int:product_id>', methods=['GET'])
@login_required
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash("Товар успешно удален!", "success")
    return redirect(url_for('catalog'))

@app.context_processor
def inject_user():
    user = None
    is_admin = False
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            is_admin = user.is_admin
    return dict(current_user=user, is_admin=is_admin)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash("Вы должны быть авторизованы, чтобы добавить товар в корзину.", "error")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    product = Product.query.get(product_id)

    if not product:
        flash("Товар не найден.", "error")
        return redirect(url_for('catalog'))

    # Проверяем, есть ли уже товар в корзине
    cart_item = CartItem.query.filter_by(user_id=user.id, product_id=product.id).first()

    if cart_item:
        cart_item.quantity += 1  # Если товар уже есть, увеличиваем количество
    else:
        cart_item = CartItem(user_id=user.id, product_id=product.id, quantity=1)  # Добавляем новый товар

    db.session.add(cart_item)
    db.session.commit()
    flash("Товар добавлен в корзину.", "success")

    return redirect(url_for('catalog'))



@app.route('/remove_from_cart/<int:item_id>', methods=['GET'])
def remove_from_cart(item_id):
    item = CartItem.query.get(item_id)
    if item and item.user_id == session.get('user_id'):
        db.session.delete(item)
        db.session.commit()
        flash("Товар удален из корзины.", "success")
    else:
        flash("Товар не найден или вы не можете удалить этот товар.", "error")

    return redirect(url_for('cart'))


# Запуск приложения
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
