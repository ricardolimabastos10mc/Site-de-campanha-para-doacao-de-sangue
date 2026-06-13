import os
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# ─────────────────────────────────────
# Criando o app Flask
# ─────────────────────────────────────
app = Flask(__name__)

# Conecta ao banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///feedback.db'

# Chave secreta — carregada de uma variável de ambiente por segurança
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("Defina a variável de ambiente SECRET_KEY antes de rodar!")

# ─────────────────────────────────────
# Configurações de segurança da sessão
# ─────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True   # JavaScript não acessa o cookie
app.config['SESSION_COOKIE_SECURE']   = False  # Mude para True quando usar HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Sessão dura 30 min

# ─────────────────────────────────────
# Extensões
# ─────────────────────────────────────

# Proteção contra ataques CSRF
csrf = CSRFProtect(app)

# Banco de dados
db = SQLAlchemy(app)

# Limitador de tentativas (evita brute-force e spam)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ─────────────────────────────────────
# Senha do admin (carregada do ambiente)
# ─────────────────────────────────────
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')
if not ADMIN_PASSWORD_HASH:
    raise ValueError("Defina a variável de ambiente ADMIN_PASSWORD_HASH antes de rodar!")

# ─────────────────────────────────────
# Modelo do banco de dados
# ─────────────────────────────────────
class Feedback(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    name    = db.Column(db.String(100), nullable=False)
    email   = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)

# ─────────────────────────────────────
# Decorator — protege páginas do admin
# ─────────────────────────────────────
def login_required_custom(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Se não estiver logado, manda pro login
        if not session.get('admin_logado'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ─────────────────────────────────────
# Cabeçalhos de segurança (em toda resposta)
# ─────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']         = 'SAMEORIGIN'
    response.headers['X-XSS-Protection']        = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://unpkg.com 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' https://www.cbm.df.gov.br data:;"
    )
    return response

# ─────────────────────────────────────
# Rotas públicas
# ─────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/criadores')
def criadores():
    return render_template('criadores.html')


@app.route('/feedback', methods=['POST'])
@limiter.limit("10 per minute")  # Máximo 10 envios por minuto
def feedback():
    nome     = request.form.get('name', '').strip()
    email    = request.form.get('email', '').strip()
    mensagem = request.form.get('message', '').strip()

    # Verifica se os campos foram preenchidos
    if not nome or not email or not mensagem:
        flash('Por favor, preencha todos os campos!', 'error')
        return redirect(url_for('index', _anchor='feedback'))

    # Verifica se o texto não é longo demais
    if len(mensagem) > 500 or len(nome) > 100:
        flash('Texto muito longo! Por favor, seja mais breve.', 'error')
        return redirect(url_for('index', _anchor='feedback'))

    # Salva no banco de dados
    novo_feedback = Feedback(name=nome, email=email, message=mensagem)
    db.session.add(novo_feedback)
    db.session.commit()

    flash('Sua mensagem foi enviada com sucesso! ❤️', 'success')
    return redirect(url_for('index'))

# ─────────────────────────────────────
# Rotas de autenticação
# ─────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Máximo 5 tentativas por minuto
def login():
    if request.method == 'POST':
        senha_digitada = request.form.get('password', '')

        # Confere se a senha bate com o hash salvo
        if check_password_hash(ADMIN_PASSWORD_HASH, senha_digitada):
            session.permanent = True
            session['admin_logado'] = True
            return redirect(url_for('admin'))
        else:
            flash('Credenciais inválidas!', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()  # Apaga todos os dados da sessão
    return redirect(url_for('index'))

# ─────────────────────────────────────
# Rotas do admin
# ─────────────────────────────────────
@app.route('/admin')
@login_required_custom
def admin():
    feedbacks = Feedback.query.order_by(Feedback.id.desc()).all()
    total     = len(feedbacks)
    return render_template('admin.html', feedbacks=feedbacks, total=total)


@app.route('/admin/delete/<int:id>', methods=['POST'])
@login_required_custom
def delete_feedback(id):
    fb = Feedback.query.get_or_404(id)
    db.session.delete(fb)
    db.session.commit()
    flash('Mensagem apagada!', 'success')
    return redirect(url_for('admin'))

# ─────────────────────────────────────
# Iniciando o servidor
# ─────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Cria as tabelas se não existirem
    app.run(debug=True)