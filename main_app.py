import os, sqlite3
from flask import Flask, render_template, g
from flask_login import LoginManager, UserMixin
# flexible의 views에서 필요한 것들을 가져옵니다.
from flexible.views import flexible_bp

app = Flask(__name__)
app.secret_key = 'yuseong_admin_key'

# [핵심 기능 1] 템플릿 환경 설정 (모든 앱 공용)
app.jinja_env.add_extension('jinja2.ext.do')
app.jinja_env.add_extension('jinja2.ext.loopcontrols')

# [핵심 기능 2] 통합 로그인 관리
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'flexible.login' # 공통 로그인 페이지

class User(UserMixin):
    def __init__(self, id, name, password, is_admin=0):
        self.id = id
        self.name = name
        self.password = password
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    # 각 앱이 개별 DB를 쓰므로, 메인 사용자 DB가 있는 곳에서 가져옵니다.
    from flexible.views import get_db
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user: return None
    return User(id=user['id'], name=user['name'], password=user['password'], is_admin=user['is_admin'])

# [핵심 기능 3] 프로젝트 등록
app.register_blueprint(flexible_bp, url_prefix='/flexible')
# app.register_blueprint(shelteron_bp, url_prefix='/shelteron') # 추가 예정
# app.register_blueprint(nuclear_bp, url_prefix='/nuclear')     # 추가 예정

@app.route('/')
def index():
    # 3개 프로젝트 현황을 보여주는 메인 대시보드
    stats = {'flexible': 15, 'shelteron': 8, 'nuclear': 120}
    return render_template('index.html', stats=stats)

if __name__ == '__main__':
    # 구청 환경을 고려한 포트 설정
    app.run(debug=True, host='0.0.0.0', port=80)