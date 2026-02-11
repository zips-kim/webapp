import FinanceDataReader as fdr
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

print("1. 데이터 수집 중... (한화엔진 + 환율)") 
# 1. 데이터 준비 (한화엔진: 082740, 환율: USD/KRW)
stock = fdr.DataReader('082740', '2023-01-01') # 주가
exchange = fdr.DataReader('USD/KRW', '2023-01-01') # 환율

# 데이터 합치기 (날짜 기준) - 환율 종가(Close)를 'USD'라는 이름으로 추가
df = pd.merge(stock, exchange['Close'], left_index=True, right_index=True, suffixes=('', '_USD'))
df = df.rename(columns={'Close_USD': 'USD'})

# 2. 정답지 만들기 (Labeling)
# 내일의 종가가 오늘의 종가보다 높으면 1 (상승), 아니면 0 (하락)
df['Tomorrow_Close'] = df['Close'].shift(-1) # 한 칸씩 위로 당기기
df['Target'] = (df['Tomorrow_Close'] > df['Close']).astype(int)

# 학습에 사용할 재료 (Feature) 선정: 시가, 고가, 저가, 종가, 거래량, 환율
features = ['Open', 'High', 'Low', 'Close', 'Volume', 'USD']
df = df.dropna() # 데이터가 빈 곳은 삭제

# 3. 훈련용과 검증용 데이터 나누기
# 과거 데이터로 공부하고, 최근 데이터로 시험 봅니다.
X = df[features]
y = df['Target']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, shuffle=False)

# 4. 모델 학습 (AI 훈련)
# RandomForest: 수많은 질문(나무)을 던져서 확률을 계산하는 강력한 모델
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. 검증 및 결과 확인
predictions = model.predict(X_test)
score = accuracy_score(y_test, predictions)
print(f"👉 AI의 예측 정확도: {score*100:.2f}%")

# 6. 실전! 오늘 데이터를 보고 내일(미래) 예측하기
last_data = df.iloc[[-1]][features] # 가장 최근(오늘) 데이터
prob = model.predict_proba(last_data) # 확률 계산

print("-" * 30)
print(f"📅 기준일: {last_data.index[0].date()}")
print(f"📉 내일 하락할 확률: {prob[0][0]*100:.1f}%")
print(f"📈 내일 상승할 확률: {prob[0][1]*100:.1f}%")
print("-" * 30)

if prob[0][1] > 0.7:
    print("🤖 AI 의견: 상승 확률이 70%가 넘습니다! (매수 고려)")
elif prob[0][0] > 0.7:
    print("🤖 AI 의견: 하락 확률이 높습니다. (조심하세요)")
else:
    print("🤖 AI 의견: 확실하지 않습니다. (관망 추천)")