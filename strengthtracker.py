"""
StrengthTracker — Multi-User Edition
=====================================
Per-user data isolation with simple username/password auth.
Each user sees only their own lifts, predictions, and history.

Deploy to Streamlit Cloud: share.streamlit.io
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta, date
import sqlite3
import json
import hashlib
import secrets
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Tuple
import io

DB_PATH = "strengthtracker.db"

st.set_page_config(
    page_title="StrengthTracker",
    page_icon="💪",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    .stButton>button { min-height: 44px; font-weight: 600; border-radius: 8px; }
    .stNumberInput input, .stTextInput input, .stSelectbox select { min-height: 44px; }
    .metric-card {
        background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
        border-radius: 12px; padding: 16px; color: white;
        margin-bottom: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-label {
        font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;
        opacity: 0.8; margin-bottom: 4px;
    }
    .metric-value { font-size: 1.5rem; font-weight: 700; }
    .prediction-card {
        background: linear-gradient(135deg, #134e4a 0%, #0f2e2b 100%);
        border-radius: 12px; padding: 20px; color: white;
        text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.15);
    }
    .prediction-main { font-size: 2.2rem; font-weight: 800; }
    .prediction-ci { font-size: 0.9rem; opacity: 0.85; margin-top: 4px; }
    h1, h2, h3 { color: #e0e7ff; }
    .auth-box {
        max-width: 400px; margin: 60px auto;
        background: #1e293b; border-radius: 16px;
        padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.3);
    }
    @media (max-width: 768px) {
        .block-container { padding: 1rem 0.5rem; }
    }
</style>
""", unsafe_allow_html=True)

# =============================================================================
# AUTH HELPERS
# =============================================================================
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return hashed, salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    check, _ = hash_password(password, salt)
    return check == hashed

# =============================================================================
# DATABASE (Multi-User)
# =============================================================================
class Database:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._init_tables()

    def _get_conn(self):
        return sqlite3.connect(self.path)

    def _init_tables(self):
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS lifts (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, name),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS workouts (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    lift_id INTEGER NOT NULL,
                    date TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (lift_id) REFERENCES lifts(id)
                );
                CREATE TABLE IF NOT EXISTS sets (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    workout_id INTEGER NOT NULL,
                    set_number INTEGER NOT NULL,
                    weight REAL NOT NULL,
                    reps INTEGER NOT NULL,
                    rir INTEGER NOT NULL DEFAULT 3,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (workout_id) REFERENCES workouts(id)
                );
                CREATE TABLE IF NOT EXISTS model_params (
                    user_id INTEGER NOT NULL,
                    lift_id INTEGER NOT NULL,
                    params TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, lift_id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (lift_id) REFERENCES lifts(id)
                );
            """)

    def create_user(self, username: str, password: str) -> Optional[int]:
        hashed, salt = hash_password(password)
        with self._get_conn() as conn:
            try:
                c = conn.execute(
                    "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                    (username, hashed, salt)
                )
                return c.lastrowid
            except sqlite3.IntegrityError:
                return None

    def authenticate(self, username: str, password: str) -> Optional[int]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT id, password_hash, salt FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            if row and verify_password(password, row[1], row[2]):
                return row[0]
            return None

    def add_lift(self, user_id: int, name: str) -> int:
        with self._get_conn() as conn:
            try:
                c = conn.execute(
                    "INSERT INTO lifts (user_id, name) VALUES (?, ?)",
                    (user_id, name)
                )
                return c.lastrowid
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT id FROM lifts WHERE user_id = ? AND name = ?",
                    (user_id, name)
                ).fetchone()
                return row[0]

    def get_lifts(self, user_id: int) -> List[Dict]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM lifts WHERE user_id = ? ORDER BY name",
                (user_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def add_workout(self, user_id: int, lift_id: int, workout_date: str, notes: str = "") -> int:
        with self._get_conn() as conn:
            c = conn.execute(
                "INSERT INTO workouts (user_id, lift_id, date, notes) VALUES (?, ?, ?, ?)",
                (user_id, lift_id, workout_date, notes)
            )
            return c.lastrowid

    def add_set(self, user_id: int, workout_id: int, set_number: int, weight: float, reps: int, rir: int):
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO sets (user_id, workout_id, set_number, weight, reps, rir) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, workout_id, set_number, weight, reps, rir)
            )

    def get_workouts_with_sets(self, user_id: int, lift_id: Optional[int] = None) -> pd.DataFrame:
        with self._get_conn() as conn:
            query = """
                SELECT 
                    w.id as workout_id, w.date, w.notes,
                    l.name as lift, l.id as lift_id,
                    s.set_number, s.weight, s.reps, s.rir
                FROM workouts w
                JOIN lifts l ON w.lift_id = l.id
                JOIN sets s ON s.workout_id = w.id
                WHERE w.user_id = ?
            """
            params = (user_id,)
            if lift_id is not None:
                query += " AND l.id = ?"
                params = (user_id, lift_id)
            query += " ORDER BY w.date, s.set_number"
            return pd.read_sql_query(query, conn, params=params)

    def get_workouts_summary(self, user_id: int, lift_id: Optional[int] = None) -> pd.DataFrame:
        with self._get_conn() as conn:
            query = """
                SELECT 
                    w.id, w.date, w.notes,
                    l.name as lift, l.id as lift_id,
                    COUNT(s.id) as num_sets,
                    GROUP_CONCAT(s.weight || 'x' || s.reps || '@' || s.rir, ', ') as sets_summary
                FROM workouts w
                JOIN lifts l ON w.lift_id = l.id
                LEFT JOIN sets s ON s.workout_id = w.id
                WHERE w.user_id = ?
            """
            params = (user_id,)
            if lift_id is not None:
                query += " AND l.id = ?"
                params = (user_id, lift_id)
            query += " GROUP BY w.id ORDER BY w.date DESC"
            return pd.read_sql_query(query, conn, params=params)

    def delete_workout(self, user_id: int, workout_id: int):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM sets WHERE user_id = ? AND workout_id = ?", (user_id, workout_id))
            conn.execute("DELETE FROM workouts WHERE user_id = ? AND id = ?", (user_id, workout_id))

    def save_params(self, user_id: int, lift_id: int, params: dict):
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO model_params (user_id, lift_id, params) VALUES (?, ?, ?)
                   ON CONFLICT(user_id, lift_id) DO UPDATE SET params=excluded.params, updated_at=CURRENT_TIMESTAMP""",
                (user_id, lift_id, json.dumps(params))
            )

    def load_params(self, user_id: int, lift_id: int) -> Optional[dict]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT params FROM model_params WHERE user_id = ? AND lift_id = ?",
                (user_id, lift_id)
            ).fetchone()
            return json.loads(row[0]) if row else None


# =============================================================================
# DATA MODELS
# =============================================================================
@dataclass
class WorkoutSet:
    weight: float
    reps: int
    rir: int
    set_number: int = 1

    def effective_reps(self) -> int:
        return self.reps + self.rir

    def estimated_1rm(self) -> float:
        er = self.effective_reps()
        if er >= 37:
            return self.weight
        return self.weight / (1.0278 - 0.0278 * er)

    def stress(self, baseline_strength: float) -> float:
        if baseline_strength <= 0:
            baseline_strength = self.weight
        rir_mult = 1.0 + 0.3 * max(0, 3 - self.rir)
        return (self.weight / baseline_strength) * self.reps * rir_mult


@dataclass
class SessionResult:
    date: str
    observed: float
    predicted: float
    residual: float
    resid_norm: float
    stress: float
    fatigue: float
    strength: float
    covariance: float
    K: float
    ci_95: float


# =============================================================================
# KALMAN FILTER
# =============================================================================
class StrengthModel:
    DEFAULT_PARAMS = {
        'mu': 0.3, 'rho': 0.70, 'alpha': 0.30, 'gamma': 8.0,
        'lambda_f': 0.60, 'Q': 2.0, 'R': 6.0,
        'beta': 1.5, 'base_K': 0.35, 'rir_scale': 0.30,
    }

    def __init__(self, initial_strength: float = 300.0, params: Optional[dict] = None):
        self.params = {**self.DEFAULT_PARAMS, **(params or {})}
        self.strength = initial_strength
        self.fatigue = 0.0
        self.covariance = 25.0
        self.history: List[SessionResult] = []
        self.avg_stress = 5.0

    def _p(self, key: str) -> float:
        return self.params[key]

    def process_session(self, session_date: str, sets: List[WorkoutSet]) -> SessionResult:
        observed = max(s.estimated_1rm() for s in sets)
        stress = sum(s.stress(self.strength) for s in sets)
        self.avg_stress = 0.9 * self.avg_stress + 0.1 * stress

        S_pred = self.strength + self._p('mu')
        P_pred = self.covariance + self._p('Q')
        F_pred = self._p('rho') * self.fatigue

        E_pred = S_pred - self._p('lambda_f') * F_pred

        resid = observed - E_pred
        resid_norm = resid / S_pred if S_pred > 0 else 0.0

        R_eff = self._p('R') * (1.0 + self._p('beta') * (resid_norm ** 2))

        K = P_pred / (P_pred + R_eff)
        K = min(K, self._p('base_K'))

        self.strength = S_pred + K * resid
        self.covariance = (1.0 - K) * P_pred

        self.fatigue = (
            self._p('rho') * self.fatigue +
            self._p('alpha') * stress +
            self._p('gamma') * max(0.0, -resid_norm)
        )

        ci_95 = 1.96 * np.sqrt(self.covariance + R_eff)

        result = SessionResult(
            date=session_date, observed=observed, predicted=E_pred,
            residual=resid, resid_norm=resid_norm, stress=stress,
            fatigue=self.fatigue, strength=self.strength,
            covariance=self.covariance, K=K, ci_95=ci_95
        )
        self.history.append(result)
        return result

    def predict_next(self, sessions_ahead: int = 1, expected_stress: Optional[float] = None) -> Tuple[float, float, float]:
        if expected_stress is None:
            expected_stress = self.avg_stress

        S_future = self.strength + sessions_ahead * self._p('mu')
        F_future = self.fatigue * (self._p('rho') ** sessions_ahead)
        for i in range(sessions_ahead):
            F_future = self._p('rho') * F_future + self._p('alpha') * expected_stress

        E_future = S_future - self._p('lambda_f') * F_future
        P_future = self.covariance + sessions_ahead * self._p('Q')
        R_future = self._p('R') * 1.1
        ci = 1.96 * np.sqrt(P_future + R_future)

        return E_future, E_future - ci, E_future + ci

    def project(self, num_sessions: int, sessions_per_week: int = 3) -> pd.DataFrame:
        projections = []
        S, F, P = self.strength, self.fatigue, self.covariance

        for i in range(1, num_sessions + 1):
            S += self._p('mu')
            F = self._p('rho') * F + self._p('alpha') * self.avg_stress
            P += self._p('Q')
            E = S - self._p('lambda_f') * F
            ci = 1.96 * np.sqrt(P + self._p('R'))
            projections.append({
                'session': i, 'week': i / sessions_per_week,
                'strength': S, 'fatigue': F, 'expected': E,
                'ci_lower': E - ci, 'ci_upper': E + ci
            })
        return pd.DataFrame(projections)


def run_model_for_lift(db: Database, user_id: int, lift_id: int, custom_params: Optional[dict] = None) -> Tuple[Optional[StrengthModel], pd.DataFrame]:
    df = db.get_workouts_with_sets(user_id, lift_id)
    if df.empty:
        return None, df

    saved = db.load_params(user_id, lift_id)
    params = {**StrengthModel.DEFAULT_PARAMS}
    if saved:
        params.update(saved)
    if custom_params:
        params.update(custom_params)

    df['date'] = pd.to_datetime(df['date'])

    first_workout = df[df['workout_id'] == df['workout_id'].iloc[0]]
    sets = [WorkoutSet(r['weight'], r['reps'], r['rir'], r['set_number']) for _, r in first_workout.iterrows()]
    initial = max(s.estimated_1rm() for s in sets)

    model = StrengthModel(initial_strength=initial, params=params)

    results = []
    for wid, group in df.groupby('workout_id'):
        group = group.sort_values('set_number')
        session_date = group['date'].iloc[0].strftime('%Y-%m-%d')
        sets = [WorkoutSet(r['weight'], r['reps'], r['rir'], r['set_number']) for _, r in group.iterrows()]
        result = model.process_session(session_date, sets)
        results.append(asdict(result))

    return model, pd.DataFrame(results)


# =============================================================================
# DEMO DATA
# =============================================================================
def generate_demo_data(db: Database, user_id: int):
    lift_id = db.add_lift(user_id, "Bench Press")
    np.random.seed(42)
    true_strength, fatigue = 295.0, 0.0
    start_date = datetime(2026, 4, 1)

    for week in range(12):
        for s in range(3):
            d = start_date + timedelta(days=week * 7 + s * 2)
            true_strength += np.random.normal(0.4, 0.2)
            fatigue *= 0.65

            if s == 0:
                sets_data, stress = [(275, 3, 2), (275, 3, 2), (275, 3, 3)], 12.0
            elif s == 1:
                sets_data, stress = [(255, 5, 3), (255, 5, 3), (255, 5, 3), (255, 5, 4)], 14.0
            else:
                sets_data, stress = [(265, 4, 2), (265, 4, 2), (265, 4, 3)], 10.0

            fatigue += stress * 0.25
            pf = 1 - 0.6 * (fatigue / 20)
            noise = np.random.normal(0, 3.5)

            wid = db.add_workout(user_id, lift_id, d.strftime('%Y-%m-%d'), f"Week {week+1} Session {s+1}")
            for i, (w, r, rir) in enumerate(sets_data):
                db.add_set(user_id, wid, i+1, round(w * pf + noise * 0.3, 1), r, rir)

    lift_id2 = db.add_lift(user_id, "Squat")
    true_strength2, fatigue2 = 405.0, 0.0
    for week in range(8):
        for s in range(2):
            d = start_date + timedelta(days=week * 7 + s * 3)
            true_strength2 += np.random.normal(0.5, 0.3)
            fatigue2 *= 0.6

            if s == 0:
                sets_data, stress = [(365, 3, 2), (365, 3, 2), (365, 3, 3)], 15.0
            else:
                sets_data, stress = [(335, 5, 3), (335, 5, 3), (335, 5, 4)], 12.0

            fatigue2 += stress * 0.3
            pf = 1 - 0.6 * (fatigue2 / 25)
            noise = np.random.normal(0, 5.0)

            wid = db.add_workout(user_id, lift_id2, d.strftime('%Y-%m-%d'), f"Week {week+1} Session {s+1}")
            for i, (w, r, rir) in enumerate(sets_data):
                db.add_set(user_id, wid, i+1, round(w * pf + noise * 0.3, 1), r, rir)


# =============================================================================
# PLOTTING
# =============================================================================
def create_dashboard_plot(model: StrengthModel, results_df: pd.DataFrame, lift_name: str, projection_weeks: int = 8):
    results_df['date'] = pd.to_datetime(results_df['date'])
    proj = model.project(num_sessions=projection_weeks * 3, sessions_per_week=3)

    last_date = results_df['date'].iloc[-1]
    future_dates = [last_date + timedelta(days=int(i*7/3)) for i in range(1, len(proj)+1)]
    proj['date'] = future_dates

    fig = make_subplots(
        rows=2, cols=1, shared_xaxes=True,
        row_heights=[0.7, 0.3], vertical_spacing=0.08,
        subplot_titles=(f"{lift_name} — Strength Trajectory", "Fatigue & Stress")
    )

    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['observed'],
        mode='markers', name='Observed 1RM',
        marker=dict(color='#f59e0b', size=10, line=dict(width=1, color='#fff')),
        hovertemplate='Date: %{x}<br>Observed: %{y:.1f} lbs<extra></extra>'
    ), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['strength'],
        mode='lines', name='True Strength (Smoothed)',
        line=dict(color='#3b82f6', width=3),
        hovertemplate='Date: %{x}<br>Strength: %{y:.1f} lbs<extra></extra>'
    ), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['predicted'],
        mode='lines', name='Expected Performance',
        line=dict(color='#10b981', width=2, dash='dot'),
        hovertemplate='Date: %{x}<br>Expected: %{y:.1f} lbs<extra></extra>'
    ), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['strength'] + results_df['ci_95'],
        mode='lines', line=dict(width=0), showlegend=False, hoverinfo='skip'
    ), row=1, col=1)
    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['strength'] - results_df['ci_95'],
        mode='lines', line=dict(width=0), fill='tonexty',
        fillcolor='rgba(59, 130, 246, 0.15)', name='95% CI', hoverinfo='skip'
    ), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=proj['date'], y=proj['expected'],
        mode='lines', name='Projected',
        line=dict(color='#8b5cf6', width=2, dash='dash'),
        hovertemplate='Date: %{x}<br>Projected: %{y:.1f} lbs<extra></extra>'
    ), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=proj['date'], y=proj['ci_upper'],
        mode='lines', line=dict(width=0), showlegend=False, hoverinfo='skip'
    ), row=1, col=1)
    fig.add_trace(go.Scatter(
        x=proj['date'], y=proj['ci_lower'],
        mode='lines', line=dict(width=0), fill='tonexty',
        fillcolor='rgba(139, 92, 246, 0.1)', showlegend=False, hoverinfo='skip'
    ), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['fatigue'],
        mode='lines', name='Fatigue',
        line=dict(color='#ef4444', width=2),
        hovertemplate='Date: %{x}<br>Fatigue: %{y:.1f}<extra></extra>'
    ), row=2, col=1)

    fig.add_trace(go.Bar(
        x=results_df['date'], y=results_df['stress'],
        name='Stress', marker_color='#f97316', opacity=0.6,
        hovertemplate='Date: %{x}<br>Stress: %{y:.2f}<extra></extra>'
    ), row=2, col=1)

    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e7ff'),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1),
        margin=dict(l=40, r=40, t=80, b=40),
        hovermode='x unified'
    )
    fig.update_yaxes(title_text='Weight (lbs)', row=1, col=1)
    fig.update_yaxes(title_text='Fatigue / Stress', row=2, col=1)
    fig.update_xaxes(title_text='Date', row=2, col=1)
    return fig


# =============================================================================
# EXPORT
# =============================================================================
def export_to_excel(db: Database, user_id: int, lift_id: Optional[int] = None) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        raw = db.get_workouts_with_sets(user_id, lift_id)
        if not raw.empty:
            raw.to_excel(writer, sheet_name='Raw Data', index=False)

        lifts = db.get_lifts(user_id)
        if lift_id:
            lifts = [l for l in lifts if l['id'] == lift_id]

        all_results = []
        for lift in lifts:
            model, results = run_model_for_lift(db, user_id, lift['id'])
            if model is not None and not results.empty:
                results['lift'] = lift['name']
                all_results.append(results)

        if all_results:
            pd.concat(all_results, ignore_index=True).to_excel(writer, sheet_name='Model Results', index=False)

        summary = db.get_workouts_summary(user_id, lift_id)
        if not summary.empty:
            summary.to_excel(writer, sheet_name='Workout Summary', index=False)
    output.seek(0)
    return output.getvalue()


# =============================================================================
# AUTH UI
# =============================================================================
def page_auth(db: Database):
    st.markdown('<div class="auth-box">', unsafe_allow_html=True)
    st.markdown("<h2 style='text-align:center;margin-bottom:4px;'> Strength Model</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;opacity:0.6;margin-bottom:24px;'>Linear Estimation Towards Linear Progression</p>", unsafe_allow_html=True)

    tab_login, tab_register = st.tabs(["Sign In", "Create Account"])

    with tab_login:
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Sign In", type="primary", use_container_width=True):
            user_id = db.authenticate(username, password)
            if user_id:
                st.session_state.user_id = user_id
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Invalid username or password.")

    with tab_register:
        new_user = st.text_input("Username", key="reg_user")
        new_pass = st.text_input("Password", type="password", key="reg_pass")
        new_pass2 = st.text_input("Confirm Password", type="password", key="reg_pass2")
        if st.button("Create Account", type="primary", use_container_width=True):
            if not new_user or not new_pass:
                st.error("Username and password are required.")
            elif new_pass != new_pass2:
                st.error("Passwords do not match.")
            else:
                user_id = db.create_user(new_user, new_pass)
                if user_id:
                    st.session_state.user_id = user_id
                    st.session_state.username = new_user
                    st.success("Account created! Signing you in...")
                    st.rerun()
                else:
                    st.error("Username already taken.")

    st.markdown('</div>', unsafe_allow_html=True)


# =============================================================================
# APP PAGES (User-Isolated)
# =============================================================================
def page_dashboard(db: Database, user_id: int):
    st.title("Model Dashboard")
    st.caption(f"Logged in as **{st.session_state.username}**")

    lifts = db.get_lifts(user_id)
    if not lifts:
        st.info("No workouts logged yet. Head to **Log Workout** to get started, or load **Demo Data** from Settings.")
        return

    lift_names = {l['name']: l['id'] for l in lifts}
    col1, col2 = st.columns([2, 1])
    with col1:
        selected_lift = st.selectbox("Select Lift", list(lift_names.keys()))
    with col2:
        projection_weeks = st.slider("Project (weeks)", 1, 16, 8)

    lift_id = lift_names[selected_lift]
    model, results = run_model_for_lift(db, user_id, lift_id)

    if model is None or results.empty:
        st.warning("No data available for this lift.")
        return

    latest = results.iloc[-1]
    pred, ci_low, ci_high = model.predict_next(sessions_ahead=1)

    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    with mcol1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">True Strength</div>
            <div class="metric-value">{latest['strength']:.1f} <small>lbs</small></div>
        </div>
        """, unsafe_allow_html=True)
    with mcol2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Current Fatigue</div>
            <div class="metric-value">{latest['fatigue']:.1f}</div>
        </div>
        """, unsafe_allow_html=True)
    with mcol3:
        delta = latest['strength'] - results.iloc[0]['strength']
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Gain</div>
            <div class="metric-value">+{delta:.1f} <small>lbs</small></div>
        </div>
        """, unsafe_allow_html=True)
    with mcol4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Sessions</div>
            <div class="metric-value">{len(results)}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(f"""
    <div class="prediction-card">
        <div class="metric-label">Next Session Prediction</div>
        <div class="prediction-main">{pred:.1f} <small>lbs</small></div>
        <div class="prediction-ci">95% Confidence Interval: {ci_low:.1f} — {ci_high:.1f} lbs</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    fig = create_dashboard_plot(model, results, selected_lift, projection_weeks)
    st.plotly_chart(fig, use_container_width=True)

    with st.expander("📋 Recent Session Details"):
        display_df = results[['date', 'observed', 'predicted', 'residual', 'stress', 'fatigue', 'strength']].tail(10)
        display_df = display_df.round(2)
        display_df.columns = ['Date', 'Observed', 'Expected', 'Residual', 'Stress', 'Fatigue', 'Smoothed Strength']
        st.dataframe(display_df, use_container_width=True, hide_index=True)


def page_log_workout(db: Database, user_id: int):
    st.title("📝 Log Workout")
    st.caption(f"Logged in as **{st.session_state.username}**")

    lifts = db.get_lifts(user_id)
    lift_options = [l['name'] for l in lifts]

    col1, col2 = st.columns(2)
    with col1:
        lift_choice = st.selectbox("Select Lift", lift_options + ["+ New Lift"])
        new_lift_name = None
        if lift_choice == "+ New Lift":
            new_lift_name = st.text_input("New Lift Name", placeholder="e.g., Overhead Press")
    with col2:
        workout_date = st.date_input("Date", value=date.today())

    notes = st.text_area("Notes (optional)", placeholder="How did it feel? Sleep? Nutrition?")

    st.markdown("### Sets")
    st.caption("Enter weight, reps, and RIR (Reps in Reserve) for each set.")

    if 'num_sets' not in st.session_state:
        st.session_state.num_sets = 3

    cols = st.columns([1, 2, 2, 2, 0.5])
    with cols[0]: st.markdown("**Set**")
    with cols[1]: st.markdown("**Weight (lbs)**")
    with cols[2]: st.markdown("**Reps**")
    with cols[3]: st.markdown("**RIR**")

    set_data = []
    for i in range(st.session_state.num_sets):
        cols = st.columns([1, 2, 2, 2, 0.5])
        with cols[0]: st.markdown(f"**{i+1}**")
        with cols[1]: weight = st.number_input(f"w_{i}", min_value=0.0, value=225.0, step=2.5, key=f"w_{i}", label_visibility="collapsed")
        with cols[2]: reps = st.number_input(f"r_{i}", min_value=1, max_value=30, value=5, step=1, key=f"r_{i}", label_visibility="collapsed")
        with cols[3]: rir = st.number_input(f"rir_{i}", min_value=0, max_value=10, value=2, step=1, key=f"rir_{i}", label_visibility="collapsed")
        set_data.append((weight, reps, rir))

    c1, c2, c3 = st.columns([1, 1, 3])
    with c1:
        if st.button("➕ Add Set", use_container_width=True):
            st.session_state.num_sets += 1
            st.rerun()
    with c2:
        if st.button("➖ Remove Set", use_container_width=True) and st.session_state.num_sets > 1:
            st.session_state.num_sets -= 1
            st.rerun()

    st.markdown("---")

    preview_sets = [WorkoutSet(w, r, rir) for w, r, rir in set_data]
    est_1rms = [s.estimated_1rm() for s in preview_sets]
    best_idx = int(np.argmax(est_1rms))

    st.markdown("**Estimated 1RMs:** " + ", ".join([f"Set {i+1}: **{e:.1f}** lbs" for i, e in enumerate(est_1rms)]))
    st.markdown(f"**Best estimated 1RM:** Set {best_idx+1} at **{est_1rms[best_idx]:.1f}** lbs")

    if st.button("💾 Save Workout", type="primary", use_container_width=True):
        if lift_choice == "+ New Lift" and (not new_lift_name or not new_lift_name.strip()):
            st.error("Please enter a name for the new lift.")
            return

        lift_name = new_lift_name if lift_choice == "+ New Lift" else lift_choice
        lid = db.add_lift(user_id, lift_name)
        wid = db.add_workout(user_id, lid, workout_date.strftime('%Y-%m-%d'), notes)

        for i, (w, r, rir_val) in enumerate(set_data):
            db.add_set(user_id, wid, i+1, w, r, rir_val)

        st.success(f"Workout saved for **{lift_name}** on {workout_date}!")
        
        st.session_state.num_sets = 3


def page_history(db: Database, user_id: int):
    st.title("📚 Workout History")
    st.caption(f"Logged in as **{st.session_state.username}**")

    lifts = db.get_lifts(user_id)
    if not lifts:
        st.info("No workouts logged yet.")
        return

    lift_names = {l['name']: l['id'] for l in lifts}
    lift_names["All Lifts"] = None

    selected = st.selectbox("Filter by Lift", list(lift_names.keys()))
    lift_id = lift_names[selected]

    summary = db.get_workouts_summary(user_id, lift_id)
    if summary.empty:
        st.info("No workouts found.")
        return

    for _, row in summary.iterrows():
        with st.container():
            c1, c2, c3 = st.columns([3, 2, 1])
            with c1:
                st.markdown(f"**{row['lift']}** — {row['date']}")
                if row['notes']:
                    st.caption(row['notes'])
            with c2:
                st.caption(f"{row['num_sets']} sets: {row['sets_summary']}")
            with c3:
                if st.button("🗑️ Delete", key=f"del_{row['id']}"):
                    db.delete_workout(user_id, row['id'])
                    st.rerun()
            st.divider()


def page_export(db: Database, user_id: int):
    st.title("📤 Export Data")
    st.caption(f"Logged in as **{st.session_state.username}**")

    lifts = db.get_lifts(user_id)
    if not lifts:
        st.info("No data to export yet.")
        return

    lift_names = {l['name']: l['id'] for l in lifts}
    lift_names["All Lifts"] = None

    selected = st.selectbox("Select Lift to Export", list(lift_names.keys()))
    lift_id = lift_names[selected]

    if st.button("📥 Download Excel", type="primary"):
        excel_data = export_to_excel(db, user_id, lift_id)
        st.download_button(
            label="Click to Download",
            data=excel_data,
            file_name=f"strengthtracker_{st.session_state.username}_{datetime.now().strftime('%Y%m%d')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    st.markdown("---")
    st.markdown("### Preview: Raw Data")
    raw = db.get_workouts_with_sets(user_id, lift_id)
    if not raw.empty:
        st.dataframe(raw, use_container_width=True, hide_index=True)

    st.markdown("### Preview: Model Results")
    if lift_id:
        model, results = run_model_for_lift(db, user_id, lift_id)
        if model is not None:
            display = results[['date', 'observed', 'predicted', 'strength', 'fatigue', 'stress', 'ci_95']].round(2)
            st.dataframe(display, use_container_width=True, hide_index=True)


def page_settings(db: Database, user_id: int):
    st.title("⚙️ Settings")
    st.caption(f"Logged in as **{st.session_state.username}**")

    st.markdown("### Model Parameters")
    st.caption("These parameters control how the Kalman Filter estimates your strength.")

    col1, col2, col3 = st.columns(3)
    with col1:
        mu = st.number_input("Progressive Gain (mu)", value=0.3, step=0.1, format="%.2f",
                             help="Expected strength gain per session (lbs)")
        rho = st.number_input("Fatigue Decay (rho)", value=0.70, step=0.05, format="%.2f",
                              help="How much fatigue carries over between sessions")
        alpha = st.number_input("Stress Accumulation (alpha)", value=0.30, step=0.05, format="%.2f",
                                help="How much session stress adds to fatigue")
    with col2:
        gamma = st.number_input("Residual Correction (gamma)", value=8.0, step=1.0, format="%.1f",
                                help="How much underperformance boosts fatigue estimate")
        lambda_f = st.number_input("Fatigue Scale (lambda_f)", value=0.60, step=0.05, format="%.2f",
                                   help="How much fatigue subtracts from performance (<1)")
        Q = st.number_input("Process Noise (Q)", value=2.0, step=0.5, format="%.1f",
                            help="Variance of random strength fluctuations")
    with col3:
        R = st.number_input("Measurement Noise (R)", value=6.0, step=0.5, format="%.1f",
                            help="Base variance of 1RM estimation error")
        beta = st.number_input("Adaptive Inflation (beta)", value=1.5, step=0.5, format="%.1f",
                               help="How much to inflate measurement noise for large residuals")
        base_K = st.number_input("Max Kalman Gain", value=0.35, step=0.05, format="%.2f",
                                 help="Cap on how much a single session can update strength")

    params = {
        'mu': mu, 'rho': rho, 'alpha': alpha, 'gamma': gamma,
        'lambda_f': lambda_f, 'Q': Q, 'R': R, 'beta': beta, 'base_K': base_K
    }

    st.markdown("---")

    lifts = db.get_lifts(user_id)
    if lifts:
        lift_names = {l['name']: l['id'] for l in lifts}
        selected = st.selectbox("Apply to Lift", list(lift_names.keys()))
        lift_id = lift_names[selected]

        if st.button("💾 Save Parameters", type="primary"):
            db.save_params(user_id, lift_id, params)
            st.success(f"Parameters saved for **{selected}**!")

    st.markdown("---")
    st.markdown("### Demo Data")
    if st.button("🎲 Generate Demo Data", help="Creates 12 weeks of Bench Press and 8 weeks of Squat"):
        generate_demo_data(db, user_id)
        st.success("Demo data generated! Go to the Dashboard.")
        st.rerun()

    st.markdown("---")
    st.markdown("### Account")
    if st.button("🚪 Sign Out", type="secondary"):
        for key in ['user_id', 'username']:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    


# =============================================================================
# MAIN
# =============================================================================
def main():
    db = Database()

    # Auth state
    if 'user_id' not in st.session_state:
        page_auth(db)
        return

    user_id = st.session_state.user_id

    # Navigation
    st.sidebar.title("Strength Model")
    st.sidebar.markdown(f"**{st.session_state.username}**")
    st.sidebar.markdown("---")

    page = st.sidebar.radio("Navigate", [
        "🏠 Dashboard",
        "📝 Log Workout",
        "📚 History",
        "📤 Export",
        "⚙️ Settings"
    ])

    st.sidebar.markdown("---")
    

    if page == "🏠 Dashboard":
        page_dashboard(db, user_id)
    elif page == "📝 Log Workout":
        page_log_workout(db, user_id)
    elif page == "📚 History":
        page_history(db, user_id)
    elif page == "📤 Export":
        page_export(db, user_id)
    elif page == "⚙️ Settings":
        page_settings(db, user_id)


if __name__ == "__main__":
    main()
