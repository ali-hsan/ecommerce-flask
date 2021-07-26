from flask_ckeditor import CKEditorField
from flask_wtf import FlaskForm
from wtforms import IntegerField, BooleanField, StringField, \
    FloatField, SubmitField, SelectField, PasswordField, validators


def create_product_form(choices):
    class ProductForm(FlaskForm):
        name = StringField('Name', [validators.DataRequired()])
        description = CKEditorField("Description", validators=[validators.DataRequired()])
        category = SelectField('Category', validators=[validators.DataRequired()],
                               choices=choices)
        create_category = StringField('Create Category (Optional)')
        price = FloatField('Price', default=0)
        discount_price = FloatField('Discount Price', default=0)
        images = StringField('Images Links (, separated)', [validators.DataRequired()])
        quantity = IntegerField('Quantity', default=0, validators=[validators.DataRequired()])
        on_sale = BooleanField('On Sale', default=False)
        submit = SubmitField()

    return ProductForm()


def create_product_edit_form(to_edit):
    class ProductEditForm(FlaskForm):
        name = StringField('Name', validators=[validators.DataRequired()], render_kw={"value": to_edit.name})
        description = CKEditorField("Description", validators=[validators.DataRequired()], default=to_edit.description)
        price = FloatField('Price', render_kw={"value": to_edit.regular_price})
        discount_price = FloatField('Discount Price', render_kw={"value": to_edit.discount_price})
        images = StringField('Images Links (, separated)', [validators.DataRequired()],
                             render_kw={"value": to_edit.images})
        quantity = IntegerField('Quantity', [validators.DataRequired()],
                                render_kw={"value": to_edit.quantity})
        on_sale = BooleanField('On Sale', default=to_edit.on_sale)
        submit = SubmitField()

    return ProductEditForm()


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[validators.DataRequired()])
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.length(8)
    ])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Log In')
