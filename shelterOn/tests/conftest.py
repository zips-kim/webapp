import pytest
from app import app as flask_app
from database import ShelterOn

@pytest.fixture
def app():
    flask_app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test_secret_key"
    })
    yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def admin_session(client):
    """관리자 권한 세션 모킹"""
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['role'] = 1  # 관리자
        sess['user_name'] = "테스트관리자"
    return client

@pytest.fixture
def staff_session(client):
    """근무자 권한 세션 모킹"""
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['role'] = 3  # 근무자
        sess['shelter_id'] = '1'
        sess['user_name'] = "테스트근무자"
    return client