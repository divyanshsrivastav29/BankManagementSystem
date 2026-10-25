import csv
import io
import os
import secrets
import uuid
from datetime import date, datetime, time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import click
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import (
    DateField,
    DecimalField,
    EmailField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
)
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    NumberRange,
    Optional,
)


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY is missing from your .env file.")

if not app.config["SQLALCHEMY_DATABASE_URI"]:
    raise RuntimeError("DATABASE_URL is missing from your .env file.")

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in first."
login_manager.login_message_category = "warning"


# =========================================================
# DATABASE MODELS
# These models map to your existing MySQL tables.
# =========================================================

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(
        db.Enum("admin", "staff", name="user_role"),
        nullable=False,
        default="staff",
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Customer(db.Model):
    __tablename__ = "customers"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    accounts = db.relationship("Account", backref="customer", lazy=True)


class Account(db.Model):
    __tablename__ = "accounts"

    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(30), unique=True, nullable=False)
    customer_id = db.Column(
        db.Integer,
        db.ForeignKey("customers.id"),
        nullable=False,
    )
    account_type = db.Column(
        db.Enum("Savings", "Current", name="account_type"),
        nullable=False,
    )
    balance = db.Column(
        db.Numeric(15, 2),
        nullable=False,
        default=Decimal("0.00"),
    )
    status = db.Column(
        db.Enum("Active", "Closed", "Frozen", name="account_status"),
        nullable=False,
        default="Active",
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    transaction_ref = db.Column(db.String(64), unique=True, nullable=False)

    account_id = db.Column(
        db.Integer,
        db.ForeignKey("accounts.id"),
        nullable=False,
    )
    related_account_id = db.Column(
        db.Integer,
        db.ForeignKey("accounts.id"),
        nullable=True,
    )

    transaction_type = db.Column(
        db.Enum(
            "Deposit",
            "Withdrawal",
            "Transfer In",
            "Transfer Out",
            name="transaction_type",
        ),
        nullable=False,
    )

    amount = db.Column(db.Numeric(15, 2), nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    account = db.relationship(
        "Account",
        foreign_keys=[account_id],
    )
    related_account = db.relationship(
        "Account",
        foreign_keys=[related_account_id],
    )


# =========================================================
# FORMS
# =========================================================

class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(max=80)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()],
    )
    submit = SubmitField("Login")

class ForgotPasswordForm(FlaskForm):
    email = EmailField(
        "Registered Email",
        validators=[
            DataRequired(),
            Email(),
            Length(max=120),
        ],
    )
    submit = SubmitField("Generate Reset Link")

class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128),
        ],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128),
        ],
    )
    submit = SubmitField("Reset Password")


class CustomerForm(FlaskForm):
    full_name = StringField(
        "Full Name",
        validators=[DataRequired(), Length(max=120)],
    )
    email = EmailField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)],
    )
    phone = StringField(
        "Phone",
        validators=[DataRequired(), Length(max=20)],
    )
    address = StringField(
        "Address",
        validators=[DataRequired(), Length(max=255)],
    )
    date_of_birth = DateField(
        "Date of Birth",
        format="%Y-%m-%d",
        validators=[Optional()],
    )
    submit = SubmitField("Save Customer")


class AccountForm(FlaskForm):
    customer_id = SelectField(
        "Customer",
        coerce=int,
        validators=[DataRequired()],
    )
    account_type = SelectField(
        "Account Type",
        choices=[
            ("Savings", "Savings"),
            ("Current", "Current"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Create Account")


# =========================================================
# LOGIN MANAGER
# =========================================================

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def get_account_number():
    """Generate a unique account number."""
    for _ in range(10):
        number = str(secrets.randbelow(9000000000) + 1000000000)

        if not Account.query.filter_by(account_number=number).first():
            return number

    raise RuntimeError("Could not generate a unique account number.")


def generate_transaction_ref():
    return uuid.uuid4().hex


def money_amount(raw_amount):
    """Validate and convert a submitted amount to Decimal."""
    amount = Decimal(str(raw_amount))

    if not amount.is_finite() or amount <= Decimal("0.00"):
        raise ValueError("Amount must be greater than zero.")

    if amount.as_tuple().exponent < -2:
        raise ValueError("Amount cannot have more than two decimal places.")

    if amount > Decimal("9999999999999.99"):
        raise ValueError("Amount is too large.")

    return amount


# =========================================================
# HOME, LOGIN AND LOGOUT
# =========================================================

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Login successful. Welcome!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html", form=form)


# =========================================================
# FORGOT PASSWORD AND RESET PASSWORD
# =========================================================

RESET_TOKEN_MAX_AGE = 15 * 60  # 15 minutes


def get_reset_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = ForgotPasswordForm()
    reset_url = None

    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        user = User.query.filter(
            func.lower(User.email) == email
        ).first()

        if user:
            token = get_reset_serializer().dumps(
                user.id,
                salt="password-reset",
            )

            reset_url = url_for(
                "reset_password",
                token=token,
                _external=True,
            )

        flash(
            "If the email is registered, a reset link can be generated.",
            "info",
        )

    return render_template(
        "forgot_password.html",
        form=form,
        reset_url=reset_url,
    )


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    try:
        user_id = get_reset_serializer().loads(
            token,
            salt="password-reset",
            max_age=RESET_TOKEN_MAX_AGE,
        )
    except SignatureExpired:
        flash(
            "This reset link has expired. Please request a new one.",
            "error",
        )
        return redirect(url_for("forgot_password"))
    except (BadSignature, TypeError, ValueError):
        flash("This reset link is invalid.", "error")
        return redirect(url_for("forgot_password"))

    user = db.session.get(User, user_id)

    if user is None:
        flash("This reset link is invalid.", "error")
        return redirect(url_for("forgot_password"))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash("The passwords do not match.", "error")
            return render_template("reset_password.html", form=form)

        user.set_password(form.password.data)

        try:
            db.session.commit()
            flash(
                "Password changed successfully. Please log in.",
                "success",
            )
            return redirect(url_for("login"))

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Password reset failed")
            flash("Could not reset the password. Please try again.", "error")

    return render_template("reset_password.html", form=form)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():
    total_customers = Customer.query.count()
    total_accounts = Account.query.count()
    total_transactions = Transaction.query.count()

    total_balance = (
        db.session.query(func.coalesce(func.sum(Account.balance), 0))
        .scalar()
    )

    return render_template(
        "dashboard.html",
        total_customers=total_customers,
        total_accounts=total_accounts,
        total_transactions=total_transactions,
        total_balance=total_balance,
    )


@app.route("/db-status")
@login_required
def db_status():
    try:
        db.session.execute(db.text("SELECT 1"))
        return {"status": "connected", "database": "available"}, 200
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Database status check failed")
        return {"status": "error", "database": "unavailable"}, 500


# =========================================================
# CUSTOMER MANAGEMENT
# =========================================================

@app.route("/customers")
@login_required
def customers():
    customer_records = Customer.query.order_by(Customer.id.desc()).all()

    return render_template(
        "customers.html",
        customers=customer_records,
    )


@app.route("/customers/add", methods=["GET", "POST"])
@login_required
def add_customer():
    form = CustomerForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        # Friendly duplicate-email validation.
        existing_customer = Customer.query.filter(
            func.lower(Customer.email) == email
        ).first()

        if existing_customer:
            flash(
                "A customer with this email already exists. "
                "Please enter a different email address.",
                "error",
            )
            return render_template("customer_form.html", form=form)

        customer = Customer(
            full_name=form.full_name.data.strip(),
            email=email,
            phone=form.phone.data.strip(),
            address=form.address.data.strip(),
            date_of_birth=form.date_of_birth.data,
        )

        try:
            db.session.add(customer)
            db.session.commit()

            flash("Customer added successfully!", "success")
            return redirect(url_for("customers"))

        except IntegrityError:
            db.session.rollback()
            flash(
                "This email address is already registered. "
                "Please use a different email address.",
                "error",
            )

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Could not add customer")
            flash("Database error: customer could not be saved.", "error")

    return render_template("customer_form.html", form=form)


@app.route("/customers/edit/<int:customer_id>", methods=["GET", "POST"])
@login_required
def edit_customer(customer_id):
    customer = db.get_or_404(Customer, customer_id)
    form = CustomerForm(obj=customer)

    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        existing_customer = Customer.query.filter(
            func.lower(Customer.email) == email,
            Customer.id != customer.id,
        ).first()

        if existing_customer:
            flash(
                "Another customer already uses this email address.",
                "error",
            )
            return render_template(
                "customer_form.html",
                form=form,
                customer=customer,
            )

        customer.full_name = form.full_name.data.strip()
        customer.email = email
        customer.phone = form.phone.data.strip()
        customer.address = form.address.data.strip()
        customer.date_of_birth = form.date_of_birth.data

        try:
            db.session.commit()
            flash("Customer updated successfully!", "success")
            return redirect(url_for("customers"))

        except IntegrityError:
            db.session.rollback()
            flash(
                "This email address is already in use.",
                "error",
            )

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Could not update customer")
            flash("Database error: customer could not be updated.", "error")

    return render_template(
        "customer_form.html",
        form=form,
        customer=customer,
    )


@app.route("/customers/delete/<int:customer_id>", methods=["POST"])
@login_required
def delete_customer(customer_id):
    customer = db.get_or_404(Customer, customer_id)

    if Account.query.filter_by(customer_id=customer.id).first():
        flash(
            "This customer has accounts. Close or handle those accounts "
            "before deleting the customer.",
            "error",
        )
        return redirect(url_for("customers"))

    try:
        db.session.delete(customer)
        db.session.commit()
        flash("Customer deleted successfully.", "success")

    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Could not delete customer")
        flash("Customer could not be deleted.", "error")

    return redirect(url_for("customers"))


# =========================================================
# ACCOUNT MANAGEMENT
# =========================================================

@app.route("/accounts")
@login_required
def accounts():
    account_records = (
        Account.query
        .order_by(Account.id.desc())
        .all()
    )

    print(
        "ACCOUNT DEBUG:",
        [
            (a.id, repr(a.account_number), a.customer_id)
            for a in account_records
        ]
    )

    return render_template(
        "accounts.html",
        accounts=account_records,
    )


@app.route("/accounts/add", methods=["GET", "POST"])
@login_required
def add_account():
    form = AccountForm()

    customer_records = Customer.query.order_by(Customer.full_name).all()
    form.customer_id.choices = [
        (customer.id, f"{customer.full_name} — {customer.email}")
        for customer in customer_records
    ]

    if not customer_records:
        flash("Add a customer before creating an account.", "warning")
        return redirect(url_for("add_customer"))

    if form.validate_on_submit():
        customer = db.session.get(Customer, form.customer_id.data)

        if customer is None:
            flash("Please select a valid customer.", "error")
            return render_template("account_form.html", form=form)

        account = Account(
            account_number=get_account_number(),
            customer_id=customer.id,
            account_type=form.account_type.data,
            balance=Decimal("0.00"),
            status="Active",
        )

        try:
            db.session.add(account)
            db.session.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for("accounts"))

        except IntegrityError:
            db.session.rollback()
            app.logger.exception("Account number conflict")
            flash("Account creation conflict. Please try again.", "error")

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Could not create account")
            flash("Database error: account could not be created.", "error")

    return render_template("account_form.html", form=form)


@app.route("/accounts/<int:account_id>/close", methods=["POST"])
@login_required
def close_account(account_id):
    """Close an account without deleting its transaction history."""
    account = db.get_or_404(Account, account_id)

    if account.status == "Closed":
        flash("This account is already closed.", "warning")
        return redirect(url_for("accounts"))

    if Decimal(str(account.balance)) != Decimal("0.00"):
        flash(
            "This account cannot be closed while its balance is not zero. "
            "Withdraw or transfer the remaining funds first.",
            "error",
        )
        return redirect(url_for("accounts"))

    try:
        account.status = "Closed"
        db.session.commit()
        flash("Account closed successfully. Transaction history was preserved.", "success")
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Account closure failed")
        flash("Could not close the account. No changes were saved.", "error")

    return redirect(url_for("accounts"))


@app.route("/accounts/<int:account_id>/delete", methods=["POST"])
@login_required
def delete_account(account_id):
    """Permanently delete only an empty account with no transaction history."""
    account = db.get_or_404(Account, account_id)

    if Decimal(str(account.balance)) != Decimal("0.00"):
        flash("Cannot delete an account with a balance. Bring the balance to zero first.", "error")
        return redirect(url_for("accounts"))

    has_transactions = Transaction.query.filter(
        db.or_(
            Transaction.account_id == account.id,
            Transaction.related_account_id == account.id,
        )
    ).first()

    if has_transactions:
        flash("This account has transaction history and cannot be deleted. Close it instead.", "error")
        return redirect(url_for("accounts"))

    try:
        db.session.delete(account)
        db.session.commit()
        flash("Account deleted successfully.", "success")
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Account deletion failed")
        flash("Could not delete the account. No changes were saved.", "error")

    return redirect(url_for("accounts"))


@app.route("/accounts/<int:account_id>")
@login_required
def account_details(account_id):
    account = db.get_or_404(Account, account_id)
    customer = db.session.get(Customer, account.customer_id)

    recent_transactions = (
        Transaction.query
        .filter_by(account_id=account.id)
        .order_by(Transaction.created_at.desc(), Transaction.id.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "account_details.html",
        account=account,
        customer=customer,
        transactions=recent_transactions,
    )


# =========================================================
# INDIVIDUAL ACCOUNT STATEMENT
# =========================================================

@app.route("/accounts/<int:account_id>/statement")
@login_required
def account_statement(account_id):
    account = db.get_or_404(Account, account_id)
    customer = db.session.get(Customer, account.customer_id)

    transactions = (
        Transaction.query
        .filter_by(account_id=account.id)
        .order_by(
            Transaction.created_at.desc(),
            Transaction.id.desc(),
        )
        .all()
    )

    return render_template(
        "account_statement.html",
        account=account,
        customer=customer,
        transactions=transactions,
    )


@app.route("/accounts/<int:account_id>/statement.pdf")
@login_required
def download_account_statement(account_id):
    from io import BytesIO
    from xml.sax.saxutils import escape

    from flask import send_file
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    account = db.get_or_404(Account, account_id)
    customer = db.session.get(Customer, account.customer_id)

    transactions = (
        Transaction.query
        .filter_by(account_id=account.id)
        .order_by(
            Transaction.created_at.desc(),
            Transaction.id.desc(),
        )
        .all()
    )

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="StatementTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=19,
        textColor=colors.HexColor("#163B65"),
        spaceAfter=12,
    ))

    elements = [
        Paragraph("BANK MANAGEMENT SYSTEM", styles["StatementTitle"]),
        Paragraph("Individual Account Statement", styles["Heading2"]),
        Spacer(1, 5 * mm),
    ]

    customer_name = escape(customer.full_name if customer else "Unavailable")
    account_number = escape(str(account.account_number))
    account_type = escape(str(account.account_type))
    account_status = escape(str(account.status))

    account_info = [
        ["Account Holder", customer_name,
         "Account Number", account_number],
        ["Account Type", account_type,
         "Account Status", account_status],
        ["Current Balance", f"INR {Decimal(str(account.balance)):,.2f}",
         "Total Transactions", str(len(transactions))],
    ]

    info_table = Table(
        account_info,
        colWidths=[35 * mm, 65 * mm, 35 * mm, 65 * mm],
    )
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF0F8")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#EAF0F8")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#243247")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DCE5")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))

    elements.extend([info_table, Spacer(1, 8 * mm)])

    rows = [[
        "Transaction Reference",
        "Date & Time",
        "Transaction Type",
        "Amount (INR)",
        "Description",
    ]]

    for transaction in transactions:
        description = escape(
            (transaction.description or "-").replace("\n", " ")
        )

        rows.append([
            escape(str(transaction.transaction_ref or "-")),
            transaction.created_at.strftime("%d-%m-%Y %H:%M")
            if transaction.created_at else "-",
            escape(str(transaction.transaction_type)),
            f"{Decimal(str(transaction.amount)):,.2f}",
            Paragraph(description, styles["BodyText"]),
        ])

    if not transactions:
        rows.append(["No transactions found", "", "", "", ""])

    statement_table = Table(
        rows,
        repeatRows=1,
        colWidths=[42 * mm, 35 * mm, 35 * mm, 35 * mm, 95 * mm],
    )

    statement_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163B65")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DCE5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white, colors.HexColor("#F2F6FA")
        ]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    elements.append(statement_table)

    document.build(elements)
    buffer.seek(0)

    safe_account_number = "".join(
        char for char in str(account.account_number)
        if char.isalnum() or char in "-_"
    )

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"account_statement_{safe_account_number}.pdf",
    )


# =========================================================
# DEPOSITS AND WITHDRAWALS
# =========================================================

def process_account_operation(account_id, operation):
    if operation not in ("deposit", "withdraw"):
        abort(404)

    if request.method == "GET":
        account = db.get_or_404(Account, account_id)

        return render_template(
            "operation_form.html",
            account=account,
            operation=operation,
        )

    raw_amount = (request.form.get("amount") or "").strip()

    try:
        amount = money_amount(raw_amount)
    except (InvalidOperation, ValueError):
        flash(
            "Enter a valid amount greater than zero with no more "
            "than two decimal places.",
            "error",
        )
        return redirect(url_for(operation, account_id=account_id))

    try:
        account = (
            Account.query
            .filter_by(id=account_id)
            .with_for_update()
            .first()
        )

        if account is None:
            db.session.rollback()
            abort(404)

        if account.status != "Active":
            db.session.rollback()
            flash("This account is not active.", "error")
            return redirect(url_for("account_details", account_id=account_id))

        current_balance = Decimal(str(account.balance))

        if operation == "withdraw" and current_balance < amount:
            db.session.rollback()
            flash("Insufficient account balance.", "error")
            return redirect(url_for("withdraw", account_id=account_id))

        if operation == "deposit":
            new_balance = current_balance + amount
        else:
            new_balance = current_balance - amount

        if new_balance > Decimal("9999999999999.99"):
            db.session.rollback()
            flash("The resulting balance is too large.", "error")
            return redirect(url_for(operation, account_id=account_id))

        account.balance = new_balance

        transaction = Transaction(
            transaction_ref=generate_transaction_ref(),
            account_id=account.id,
            related_account_id=None,
            transaction_type=(
                "Deposit" if operation == "deposit" else "Withdrawal"
            ),
            amount=amount,
            description=f"{operation.title()} transaction",
        )

        db.session.add(transaction)
        db.session.commit()

        flash(
            f"{operation.title()} of ₹{amount:.2f} completed successfully.",
            "success",
        )
        return redirect(url_for("account_details", account_id=account_id))

    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Account operation failed")
        flash("Transaction failed. No changes were saved.", "error")
        return redirect(url_for(operation, account_id=account_id))


@app.route("/accounts/<int:account_id>/deposit", methods=["GET", "POST"])
@login_required
def deposit(account_id):
    return process_account_operation(account_id, "deposit")


@app.route("/accounts/<int:account_id>/withdraw", methods=["GET", "POST"])
@login_required
def withdraw(account_id):
    return process_account_operation(account_id, "withdraw")


# =========================================================
# TRANSACTION HISTORY
# =========================================================

@app.route("/transactions")
@login_required
def transaction_history():
    transaction_records = (
        db.session.query(Transaction, Account)
        .join(Account, Transaction.account_id == Account.id)
        .order_by(
            Transaction.created_at.desc(),
            Transaction.id.desc(),
        )
        .limit(200)
        .all()
    )

    return render_template(
        "transaction_history.html",
        transaction_records=transaction_records,
    )


# =========================================================
# MONEY TRANSFER BETWEEN ACCOUNTS
# =========================================================

@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer_money():
    if request.method == "GET":
        active_accounts = (
            Account.query
            .filter_by(status="Active")
            .order_by(Account.account_number)
            .all()
        )

        return render_template(
            "transfer_form.html",
            accounts=active_accounts,
        )

    try:
        source_id = int(request.form.get("source_account", ""))
        destination_id = int(request.form.get("destination_account", ""))
    except (TypeError, ValueError):
        flash("Select valid source and destination accounts.", "error")
        return redirect(url_for("transfer_money"))

    if source_id == destination_id:
        flash(
            "Source and destination accounts must be different.",
            "error",
        )
        return redirect(url_for("transfer_money"))

    try:
        amount = money_amount(request.form.get("amount", ""))
    except (InvalidOperation, ValueError):
        flash("Enter a valid transfer amount.", "error")
        return redirect(url_for("transfer_money"))

    try:
        locked_accounts = (
            Account.query
            .filter(Account.id.in_([source_id, destination_id]))
            .order_by(Account.id)
            .with_for_update()
            .all()
        )

        accounts_by_id = {
            account.id: account for account in locked_accounts
        }

        source = accounts_by_id.get(source_id)
        destination = accounts_by_id.get(destination_id)

        if source is None or destination is None:
            db.session.rollback()
            flash("One or both accounts were not found.", "error")
            return redirect(url_for("transfer_money"))

        if source.status != "Active" or destination.status != "Active":
            db.session.rollback()
            flash("Both accounts must be active.", "error")
            return redirect(url_for("transfer_money"))

        source_balance = Decimal(str(source.balance))
        destination_balance = Decimal(str(destination.balance))

        if source_balance < amount:
            db.session.rollback()
            flash("Insufficient balance in the source account.", "error")
            return redirect(url_for("transfer_money"))

        new_destination_balance = destination_balance + amount

        if new_destination_balance > Decimal("9999999999999.99"):
            db.session.rollback()
            flash("Destination balance would be too large.", "error")
            return redirect(url_for("transfer_money"))

        source.balance = source_balance - amount
        destination.balance = new_destination_balance

        db.session.add_all([
            Transaction(
                transaction_ref=generate_transaction_ref(),
                account_id=source.id,
                related_account_id=destination.id,
                transaction_type="Transfer Out",
                amount=amount,
                description=f"Transfer to account {destination.account_number}",
            ),
            Transaction(
                transaction_ref=generate_transaction_ref(),
                account_id=destination.id,
                related_account_id=source.id,
                transaction_type="Transfer In",
                amount=amount,
                description=f"Transfer from account {source.account_number}",
            ),
        ])

        db.session.commit()

        flash(
            f"₹{amount:.2f} transferred successfully.",
            "success",
        )
        return redirect(url_for("transaction_history"))

    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Money transfer failed")
        flash("Transfer failed. Database changes were rolled back.", "error")
        return redirect(url_for("transfer_money"))


# =========================================================
# REPORTS AND ANALYTICS
# =========================================================

def read_report_dates():
    """Validate optional start_date/end_date query parameters."""
    start_text = (request.args.get("start_date") or "").strip()
    end_text = (request.args.get("end_date") or "").strip()

    try:
        start_date = date.fromisoformat(start_text) if start_text else None
        end_date = date.fromisoformat(end_text) if end_text else None
    except ValueError as exc:
        raise ValueError("Please enter valid dates in YYYY-MM-DD format.") from exc

    if start_date and end_date and start_date > end_date:
        raise ValueError("Start date cannot be after end date.")

    return start_date, end_date


def get_report_transactions(start_date=None, end_date=None):
    query = Transaction.query

    if start_date:
        query = query.filter(
            Transaction.created_at >= datetime.combine(start_date, time.min)
        )
    if end_date:
        query = query.filter(
            Transaction.created_at <= datetime.combine(end_date, time.max)
        )

    return query.order_by(Transaction.created_at.desc(), Transaction.id.desc())


@app.route("/reports")
@login_required
def reports():
    try:
        start_date, end_date = read_report_dates()
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("reports"))

    total_customers = Customer.query.count()
    total_accounts = Account.query.count()
    active_accounts = Account.query.filter_by(status="Active").count()
    total_balance = (
        db.session.query(func.coalesce(func.sum(Account.balance), 0)).scalar()
    )

    transaction_records = get_report_transactions(start_date, end_date).all()

    def total_for(transaction_type):
        return sum(
            (Decimal(str(item.amount)) for item in transaction_records
             if item.transaction_type == transaction_type),
            Decimal("0.00"),
        )

    return render_template(
        "reports.html",
        total_customers=total_customers,
        total_accounts=total_accounts,
        active_accounts=active_accounts,
        total_balance=total_balance,
        transaction_count=len(transaction_records),
        deposit_total=total_for("Deposit"),
        withdrawal_total=total_for("Withdrawal"),
        transfer_out_total=total_for("Transfer Out"),
        transaction_records=transaction_records[:100],
        start_date=start_date,
        end_date=end_date,
    )


@app.route("/reports/export.csv")
@login_required
def export_reports_csv():
    try:
        start_date, end_date = read_report_dates()
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("reports"))

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "Transaction Reference", "Date and Time", "Account Number",
        "Transaction Type", "Amount (INR)", "Description",
    ])

    for transaction in get_report_transactions(start_date, end_date).all():
        account = db.session.get(Account, transaction.account_id)
        writer.writerow([
            transaction.transaction_ref,
            transaction.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if transaction.created_at else "",
            account.account_number if account else "Account unavailable",
            transaction.transaction_type,
            f"{Decimal(str(transaction.amount)):.2f}",
            transaction.description or "",
        ])

    from flask import Response
    response = Response("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = (
        "attachment; filename=bank_transaction_report.csv"
    )
    return response


@app.route("/reports/export.pdf")
@login_required
def export_reports_pdf():
    try:
        start_date, end_date = read_report_dates()
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("reports"))

    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )

    transactions = get_report_transactions(start_date, end_date).all()

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="BankTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=19,
        spaceAfter=8,
    ))

    elements = [
        Paragraph("BANK MANAGEMENT SYSTEM", styles["BankTitle"]),
        Paragraph("Transaction Report", styles["Heading2"]),
        Spacer(1, 5 * mm),
    ]

    date_range = (
        f"{start_date.strftime('%d-%m-%Y') if start_date else 'Beginning'}"
        f" to "
        f"{end_date.strftime('%d-%m-%Y') if end_date else 'Today'}"
    )
    elements.append(Paragraph(
        f"<b>Report period:</b> {date_range}",
        styles["Normal"],
    ))
    elements.append(Paragraph(
        f"<b>Total transactions:</b> {len(transactions)}",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 5 * mm))

    rows = [[
        "Reference", "Date & Time", "Account Number",
        "Type", "Amount (INR)", "Description",
    ]]

    for transaction in transactions:
        account = db.session.get(Account, transaction.account_id)

        description = (transaction.description or "").replace("\n", " ")
        description = description[:100]

        rows.append([
            str(transaction.transaction_ref or ""),
            transaction.created_at.strftime("%d-%m-%Y %H:%M")
            if transaction.created_at else "",
            str(account.account_number if account else "Unavailable"),
            str(transaction.transaction_type),
            f"{Decimal(str(transaction.amount)):.2f}",
            description,
        ])

    if not transactions:
        rows.append(["No transactions found", "", "", "", "", ""])

    table = Table(
        rows,
        repeatRows=1,
        colWidths=[35 * mm, 32 * mm, 32 * mm, 27 * mm, 30 * mm, 85 * mm],
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163B65")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("LEADING", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DCE5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white, colors.HexColor("#F2F6FA")
        ]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(table)

    document.build(elements)
    buffer.seek(0)

    from flask import send_file
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="bank_transaction_report.pdf",
    )


# =========================================================
# COMMAND-LINE ADMIN CREATION
# Usage: flask --app app create-admin
# =========================================================

@app.cli.command("create-admin")
def create_admin():
    """Create an administrator without storing a plain-text password."""
    username = click.prompt("Admin username").strip()
    email = click.prompt("Admin email").strip().lower()
    password = click.prompt("Admin password", hide_input=True, confirmation_prompt=True)

    if not username or not email or not password:
        raise click.ClickException("Username, email and password are required.")

    if User.query.filter(
        db.or_(
            func.lower(User.username) == username.lower(),
            func.lower(User.email) == email,
        )
    ).first():
        raise click.ClickException("That username or email already exists.")

    user = User(
        username=username,
        email=email,
        role="admin",
    )
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
        click.echo("Administrator created successfully.")

    except SQLAlchemyError:
        db.session.rollback()
        raise click.ClickException("Could not create administrator.")


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def page_not_found(error):
    return "Page not found.", 404


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)