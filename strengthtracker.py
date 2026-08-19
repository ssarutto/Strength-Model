"""
StrengthTracker — Streamlined Multi-User Edition
=================================================


Features:
  - Expandable full-screen graph (click to examine, click away to close)
  - Info popovers on every dashboard metric
  - Programming assistant: input reps/sets/RIR → get recommended weight

Deploy: streamlit run strengthtracker.py
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
        position: relative;
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
        margin-bottom: 20px;
    }
    .prediction-main { font-size: 2.2rem; font-weight: 800; }
    .prediction-ci { font-size: 0.9rem; opacity: 0.85; margin-top: 4px; }
    .prog-card {
        background: #1e293b; border-radius: 12px; padding: 20px;
        border: 1px solid #334155;
    }
    h1, h2, h3 { color: #e0e7ff; }
    .auth-box {
        max-width: 400px; margin: 60px auto;
        background: #1e293b; border-radius: 16px;
        padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.3);
    }
    /* Dialog override for full-screen feel */
    [data-testid="stDialog"] > div > div {
        max-width: 95vw !important;
        width: 95vw !important;
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
        """Temporary set-level capacity observation using RIR-adjusted Brzycki."""
        er = self.effective_reps()
        if er >= 37:
            return self.weight
        return self.weight / (1.0278 - 0.0278 * er)

    def observation_variance(self, sigma_obs: float, sigma_rir: float) -> float:
        """R_tj = sigma_obs^2 + (sigma_rir * RIR)^2."""
        return sigma_obs ** 2 + (sigma_rir * max(0, self.rir)) ** 2

    def dose(self, available_capacity: float, intensity_p: float, rir_penalty_c: float, rir_threshold: float) -> float:
        """Dimensionless training dose; converted to fatigue later by parameter b."""
        capacity = max(float(available_capacity), 1.0)
        rel_intensity = self.weight / capacity
        rir_mult = 1.0 + rir_penalty_c * max(0.0, rir_threshold - self.rir)
        return self.reps * (rel_intensity ** intensity_p) * rir_mult


@dataclass
class SessionResult:
    date: str
    days_since_prior: float
    num_sets: int
    observed: float                 # inverse-variance weighted mean; display only
    predicted: float                # pre-session predicted available capacity S^- - F^-
    residual: float                 # observed - predicted; display only
    mean_abs_z: float               # mean standardized innovation across set updates
    stress: float                   # dimensionless session dose U_t
    fatigue_pre: float              # posterior fatigue after set observations, before session dose
    fatigue: float                  # post-session fatigue carried forward
    strength: float                 # posterior latent fresh strength
    available_pre_stress: float     # S - F after observation updates
    available_post_stress: float    # S - F after adding this session's fatigue dose
    p_ss: float
    p_sf: float
    p_ff: float
    strength_ci_95: float
    capacity_ci_95: float


# =============================================================================
# JOINT STRENGTH / FATIGUE STATE-SPACE FILTER
# =============================================================================
class StrengthModel:
    """
    Two-state linear-Gaussian prototype.

    State:      x_t = [S_t, F_t]^T
    Observation y_tj = [1, -1] x_t + epsilon_tj

    S is latent fresh 1RM-equivalent strength (lb).
    F is fatigue in the same lb-equivalent performance-suppression units.
    Training dose is dimensionless and is applied *after* session observations.
    """

    DEFAULT_PARAMS = {
        # Time evolution
        'g_per_day': 0.0,          # lb/day; intentionally zero in the minimal model
        'rho_day': 0.75,           # fraction of fatigue retained after one day
        'q_strength_day': 1.0,     # strength process innovation variance, lb^2/day
        'q_fatigue_day': 4.0,      # one-day fatigue process innovation variance, lb^2/day

        # Training-dose model U_t
        'b': 1.0,                  # lb fatigue per dose unit
        'intensity_p': 2.0,        # super-linear intensity exponent
        'rir_penalty_c': 0.30,     # proximity-to-failure penalty slope
        'rir_threshold': 3.0,      # penalty begins below this RIR

        # Set-level observation model
        'sigma_obs': 7.5,          # baseline set-observation SD, lb
        'sigma_rir': 2.0,          # additional SD per reported RIR, lb

        # Robust innovation-based variance inflation
        'robust_beta': 1.0,
        'robust_z0': 2.5,

        # First-session identification uncertainty
        'init_fatigue_sd': 10.0,   # uncertainty in first-session fatigue, lb
    }

    H = np.array([[1.0, -1.0]])
    I2 = np.eye(2)

    def __init__(self, params: Optional[dict] = None):
        self.params = {**self.DEFAULT_PARAMS, **(params or {})}
        self.state = np.array([300.0, 0.0], dtype=float)
        self.P = np.diag([100.0, 100.0]).astype(float)
        self.history: List[SessionResult] = []
        self.avg_stress = 8.0
        self.last_date: Optional[pd.Timestamp] = None
        self.initialized = False

    @property
    def strength(self) -> float:
        return float(self.state[0])

    @property
    def fatigue(self) -> float:
        return float(self.state[1])

    @property
    def covariance(self) -> np.ndarray:
        return self.P

    def _p(self, key: str) -> float:
        return float(self.params[key])

    def _obs_variance(self, workout_set: WorkoutSet) -> float:
        return workout_set.observation_variance(
            self._p('sigma_obs'), self._p('sigma_rir')
        )

    def _weighted_session_observation(self, sets: List[WorkoutSet]) -> Tuple[float, float]:
        """Display/initialization aggregate only; filtering itself remains set-level."""
        ys = np.array([s.estimated_1rm() for s in sets], dtype=float)
        rs = np.array([self._obs_variance(s) for s in sets], dtype=float)
        weights = 1.0 / rs
        mean = float(np.sum(weights * ys) / np.sum(weights))
        var = float(1.0 / np.sum(weights))
        return mean, var

    def _decay(self, delta_days: float) -> float:
        rho = np.clip(self._p('rho_day'), 1e-6, 1.0)
        return float(rho ** max(delta_days, 0.0))

    def _process_noise(self, delta_days: float, decay: float) -> np.ndarray:
        """
        Q(dt) for a random-walk strength state and exponentially decaying fatigue.
        q_fatigue_day is interpreted as the innovation variance accumulated over one day.
        """
        dt = max(float(delta_days), 0.0)
        q_s = self._p('q_strength_day') * dt

        rho = np.clip(self._p('rho_day'), 1e-6, 1.0)
        if dt == 0:
            q_f = 0.0
        elif abs(rho - 1.0) < 1e-9:
            q_f = self._p('q_fatigue_day') * dt
        else:
            q_f = self._p('q_fatigue_day') * (1.0 - decay ** 2) / (1.0 - rho ** 2)

        return np.array([[q_s, 0.0], [0.0, q_f]], dtype=float)

    def _predict_state(self, state: np.ndarray, P: np.ndarray, delta_days: float) -> Tuple[np.ndarray, np.ndarray]:
        dt = max(float(delta_days), 0.0)
        decay = self._decay(dt)
        A = np.array([[1.0, 0.0], [0.0, decay]], dtype=float)

        x_pred = A @ state
        x_pred[0] += self._p('g_per_day') * dt
        P_pred = A @ P @ A.T + self._process_noise(dt, decay)
        P_pred = 0.5 * (P_pred + P_pred.T)
        return x_pred, P_pred

    def _set_update(self, x: np.ndarray, P: np.ndarray, workout_set: WorkoutSet) -> Tuple[np.ndarray, np.ndarray, float, float]:
        y = workout_set.estimated_1rm()
        R_base = self._obs_variance(workout_set)

        innovation = float(y - (self.H @ x)[0])
        V_base = float((self.H @ P @ self.H.T)[0, 0] + R_base)
        z = innovation / np.sqrt(max(V_base, 1e-12))

        inflation = 1.0 + self._p('robust_beta') * max(0.0, abs(z) - self._p('robust_z0')) ** 2
        R_eff = R_base * inflation
        V = float((self.H @ P @ self.H.T)[0, 0] + R_eff)

        K = (P @ self.H.T) / max(V, 1e-12)  # 2x1
        x_new = x + K[:, 0] * innovation

        # Joseph form keeps P symmetric positive semidefinite under finite precision.
        KH = K @ self.H
        P_new = (self.I2 - KH) @ P @ (self.I2 - KH).T + K * R_eff @ K.T
        P_new = 0.5 * (P_new + P_new.T)

        return x_new, P_new, innovation, z

    def initialize_first_session(self, session_date: str, sets: List[WorkoutSet]) -> SessionResult:
        """
        First-session initialization without processing the same observations twice.

        We identify available capacity C=S-F from the set observations, set the initial
        fatigue mean to zero, and retain large uncertainty in the S/F decomposition.
        """
        if not sets:
            raise ValueError("A session must contain at least one set.")

        observed, var_c = self._weighted_session_observation(sets)
        var_f = self._p('init_fatigue_sd') ** 2

        self.state = np.array([observed, 0.0], dtype=float)
        # If C and F are independent with S=C+F, then this covariance gives
        # H P H^T = Var(C) while retaining uncertainty in the S/F split.
        self.P = np.array([
            [var_c + var_f, var_f],
            [var_f, var_f],
        ], dtype=float)

        available_pre = float((self.H @ self.state)[0])
        dose = sum(
            s.dose(
                available_pre,
                self._p('intensity_p'),
                self._p('rir_penalty_c'),
                self._p('rir_threshold')
            ) for s in sets
        )
        self.avg_stress = dose

        fatigue_pre = self.fatigue
        self.state[1] += self._p('b') * dose
        available_post = float((self.H @ self.state)[0])

        strength_ci = 1.96 * np.sqrt(max(self.P[0, 0], 0.0))
        capacity_ci = 1.96 * np.sqrt(max((self.H @ self.P @ self.H.T)[0, 0], 0.0))

        self.last_date = pd.Timestamp(session_date)
        self.initialized = True

        result = SessionResult(
            date=session_date,
            days_since_prior=0.0,
            num_sets=len(sets),
            observed=observed,
            predicted=np.nan,
            residual=np.nan,
            mean_abs_z=np.nan,
            stress=dose,
            fatigue_pre=fatigue_pre,
            fatigue=self.fatigue,
            strength=self.strength,
            available_pre_stress=available_pre,
            available_post_stress=available_post,
            p_ss=float(self.P[0, 0]),
            p_sf=float(self.P[0, 1]),
            p_ff=float(self.P[1, 1]),
            strength_ci_95=float(strength_ci),
            capacity_ci_95=float(capacity_ci),
        )
        self.history.append(result)
        return result

    def process_session(self, session_date: str, sets: List[WorkoutSet]) -> SessionResult:
        if not self.initialized:
            return self.initialize_first_session(session_date, sets)
        if not sets:
            raise ValueError("A session must contain at least one set.")

        current_date = pd.Timestamp(session_date)
        delta_days = max((current_date - self.last_date).total_seconds() / 86400.0, 0.0)

        # 1-2. Recover fatigue / evolve strength and covariance over actual elapsed time.
        x, P = self._predict_state(self.state, self.P, delta_days)
        predicted_capacity = float((self.H @ x)[0])

        # Display aggregate only. The actual filter consumes every set sequentially.
        observed, _ = self._weighted_session_observation(sets)

        # 3-4. Joint set-level Kalman updates.
        innovations = []
        z_scores = []
        for workout_set in sorted(sets, key=lambda s: s.set_number):
            x, P, innovation, z = self._set_update(x, P, workout_set)
            innovations.append(innovation)
            z_scores.append(z)

        self.state = x
        self.P = P
        available_pre = float((self.H @ self.state)[0])
        fatigue_pre = self.fatigue

        # 5. Training is an input to *future* fatigue, applied after observations.
        dose = sum(
            s.dose(
                available_pre,
                self._p('intensity_p'),
                self._p('rir_penalty_c'),
                self._p('rir_threshold')
            ) for s in sets
        )
        self.avg_stress = 0.9 * self.avg_stress + 0.1 * dose
        self.state[1] += self._p('b') * dose
        available_post = float((self.H @ self.state)[0])

        strength_ci = 1.96 * np.sqrt(max(self.P[0, 0], 0.0))
        capacity_ci = 1.96 * np.sqrt(max((self.H @ self.P @ self.H.T)[0, 0], 0.0))

        result = SessionResult(
            date=session_date,
            days_since_prior=float(delta_days),
            num_sets=len(sets),
            observed=float(observed),
            predicted=float(predicted_capacity),
            residual=float(observed - predicted_capacity),
            mean_abs_z=float(np.mean(np.abs(z_scores))) if z_scores else np.nan,
            stress=float(dose),
            fatigue_pre=float(fatigue_pre),
            fatigue=self.fatigue,
            strength=self.strength,
            available_pre_stress=float(available_pre),
            available_post_stress=float(available_post),
            p_ss=float(self.P[0, 0]),
            p_sf=float(self.P[0, 1]),
            p_ff=float(self.P[1, 1]),
            strength_ci_95=float(strength_ci),
            capacity_ci_95=float(capacity_ci),
        )
        self.history.append(result)
        self.last_date = current_date
        return result

    def typical_interval_days(self) -> float:
        intervals = [h.days_since_prior for h in self.history if h.days_since_prior > 0]
        return float(np.median(intervals)) if intervals else 3.0

    def _future_observation_variance(self, expected_rir: int = 2) -> float:
        return self._p('sigma_obs') ** 2 + (self._p('sigma_rir') * expected_rir) ** 2

    def predict_next(self, days_ahead: Optional[float] = None, expected_rir: int = 2) -> Tuple[float, float, float]:
        """Predict available capacity at a future session with no intervening training."""
        if days_ahead is None:
            days_ahead = self.typical_interval_days()

        x_future, P_future = self._predict_state(self.state, self.P, days_ahead)
        expected = float((self.H @ x_future)[0])
        pred_var = float((self.H @ P_future @ self.H.T)[0, 0] + self._future_observation_variance(expected_rir))
        ci = 1.96 * np.sqrt(max(pred_var, 0.0))
        return expected, expected - ci, expected + ci

    def project(self, num_sessions: int, sessions_per_week: int = 3, expected_rir: int = 2) -> pd.DataFrame:
        """
        Project repeated future sessions at the current average dose.

        Each projected session: recover/evolve -> predict capacity -> apply one expected
        training dose to fatigue. No strength adaptation is assumed unless g_per_day != 0.
        """
        projections = []
        x = self.state.copy()
        P = self.P.copy()
        dt = 7.0 / max(float(sessions_per_week), 1.0)

        for i in range(1, num_sessions + 1):
            x, P = self._predict_state(x, P, dt)
            expected = float((self.H @ x)[0])
            pred_var = float((self.H @ P @ self.H.T)[0, 0] + self._future_observation_variance(expected_rir))
            ci = 1.96 * np.sqrt(max(pred_var, 0.0))

            projections.append({
                'session': i,
                'week': i / sessions_per_week,
                'strength': float(x[0]),
                'fatigue_pre': float(x[1]),
                'expected': expected,
                'ci_lower': expected - ci,
                'ci_upper': expected + ci,
            })

            # Planned session occurs after the prediction and affects subsequent sessions.
            x[1] += self._p('b') * self.avg_stress

        return pd.DataFrame(projections)


def run_model_for_lift(db: Database, user_id: int, lift_id: int, custom_params: Optional[dict] = None) -> Tuple[Optional[StrengthModel], pd.DataFrame]:
    df = db.get_workouts_with_sets(user_id, lift_id)
    if df.empty:
        return None, df

    saved = db.load_params(user_id, lift_id)
    params = {**StrengthModel.DEFAULT_PARAMS}
    if saved:
        # Old saved keys are harmless; only keys used by the revised model are read.
        params.update(saved)
    if custom_params:
        params.update(custom_params)

    df['date'] = pd.to_datetime(df['date'])
    df = df.sort_values(['date', 'workout_id', 'set_number'])

    model = StrengthModel(params=params)
    results = []

    for _, group in df.groupby('workout_id', sort=False):
        group = group.sort_values('set_number')
        session_date = group['date'].iloc[0].strftime('%Y-%m-%d')
        sets = [
            WorkoutSet(float(r['weight']), int(r['reps']), int(r['rir']), int(r['set_number']))
            for _, r in group.iterrows()
        ]
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
    typical_days = max(model.typical_interval_days(), 0.25)
    sessions_per_week = 7.0 / typical_days
    num_sessions = max(1, int(np.ceil(projection_weeks * sessions_per_week)))
    proj = model.project(num_sessions=num_sessions, sessions_per_week=sessions_per_week)

    last_date = results_df['date'].iloc[-1]
    future_dates = [last_date + timedelta(days=i * typical_days) for i in range(1, len(proj) + 1)]
    proj['date'] = future_dates

    fig = make_subplots(
        rows=2, cols=1, shared_xaxes=True,
        row_heights=[0.7, 0.3], vertical_spacing=0.08,
        subplot_titles=(f"{lift_name} — Strength Trajectory", "Fatigue & Training Dose")
    )

    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['observed'],
        mode='markers', name='Set-weighted Capacity Observation',
        marker=dict(color='#f59e0b', size=10, line=dict(width=1, color='#fff')),
        hovertemplate='Date: %{x}<br>Observed capacity: %{y:.1f} lbs<extra></extra>'
    ), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['strength'],
        mode='lines', name='Latent Fresh Strength',
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
        x=results_df['date'], y=results_df['strength'] + results_df['strength_ci_95'],
        mode='lines', line=dict(width=0), showlegend=False, hoverinfo='skip'
    ), row=1, col=1)
    fig.add_trace(go.Scatter(
        x=results_df['date'], y=results_df['strength'] - results_df['strength_ci_95'],
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
        mode='lines', name='Fatigue (lb suppression)',
        line=dict(color='#ef4444', width=2),
        hovertemplate='Date: %{x}<br>Fatigue: %{y:.1f}<extra></extra>'
    ), row=2, col=1)

    fig.add_trace(go.Bar(
        x=results_df['date'], y=results_df['stress'],
        name='Training Dose', marker_color='#f97316', opacity=0.6,
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
    fig.update_yaxes(title_text='Fatigue (lb) / Dose', row=2, col=1)
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
    st.markdown("<h2 style='text-align:center;margin-bottom:4px;'>Strength Model</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;opacity:0.6;margin-bottom:24px;'>Joint State Estimation of Strength and Fatigue</p>", unsafe_allow_html=True)

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
# METRIC CARD WITH INFO POPOVER
# =============================================================================
def metric_with_info(label: str, value: str, info_text: str):
    """Render a metric card with an info popover in the top-right corner."""
    c1, c2 = st.columns([0.85, 0.15])
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        # Use a tiny bit of vertical padding to align with card top
        st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)
        with st.popover("?", use_container_width=True):
            st.markdown(info_text)


# =============================================================================
# PROGRAMMING ASSISTANT
# =============================================================================
def programming_assistant(expected_1rm: float):
    """Render the programming assistant section."""
    st.markdown("---")
    st.markdown("### Programming Assistant")
    st.caption("Enter your target rep scheme and RIR to get a recommended working weight.")

    c1, c2, c3 = st.columns(3)
    with c1:
        target_reps = st.number_input("Reps per set", min_value=1, max_value=20, value=5, step=1)
    with c2:
        target_sets = st.number_input("Number of sets", min_value=1, max_value=10, value=3, step=1)
    with c3:
        target_rir = st.number_input("Target RIR", min_value=0, max_value=10, value=2, step=1)

    effective_reps = target_reps + target_rir
    if effective_reps >= 37:
        recommended = expected_1rm
    else:
        brzycki_factor = (1.0278 - 0.0278 * effective_reps)
        recommended = expected_1rm * brzycki_factor

    # Round to nearest 2.5 lbs (standard plate increments)
    recommended_rounded = round(recommended / 2.5) * 2.5

    st.markdown(f"""
    <div class="prog-card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;">
            <div>
                <div style="font-size:0.75rem;text-transform:uppercase;opacity:0.6;letter-spacing:0.05em;">Recommended Weight</div>
                <div style="font-size:2rem;font-weight:800;color:#e0e7ff;">{recommended_rounded:.1f} <span style="font-size:1rem;opacity:0.6;">lbs</span></div>
                <div style="font-size:0.85rem;opacity:0.6;margin-top:4px;">for {target_sets} sets of {target_reps} reps @ RIR {target_rir}</div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:0.75rem;text-transform:uppercase;opacity:0.6;letter-spacing:0.05em;">Raw Calculation</div>
                <div style="font-size:1.1rem;font-weight:600;color:#94a3b8;">{recommended:.1f} lbs</div>
                <div style="font-size:0.75rem;opacity:0.5;margin-top:2px;">Brzycki factor: {brzycki_factor:.3f}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Quick reference table
    with st.expander("Quick Reference Table"):
        schemes = []
        for reps in [1, 2, 3, 4, 5, 6, 8, 10, 12]:
            for rir in [0, 1, 2, 3, 4]:
                er = reps + rir
                if er >= 37:
                    w = expected_1rm
                else:
                    w = expected_1rm * (1.0278 - 0.0278 * er)
                schemes.append({
                    'Reps': reps, 'RIR': rir, 'Eff. Reps': er,
                    'Weight (lbs)': round(round(w / 2.5) * 2.5, 1)
                })
        ref_df = pd.DataFrame(schemes)
        pivot = ref_df.pivot(index='Reps', columns='RIR', values='Weight (lbs)')
        st.dataframe(pivot, use_container_width=True)


# =============================================================================
# DASHBOARD (with graph dialog, info popovers, programming assistant)
# =============================================================================
def page_dashboard(db: Database, user_id: int):
    st.title("Model Dashboard")
    st.caption(f"Logged in as **{st.session_state.username}**")

    lifts = db.get_lifts(user_id)
    if not lifts:
        st.info("No workouts logged yet. Head to Log Workout to get started, or load Demo Data from Settings.")
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
    pred, ci_low, ci_high = model.predict_next()

    # --- Metrics with info popovers ---
    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    with mcol1:
        metric_with_info(
            "True Strength",
            f"{latest['strength']:.1f} <small>lbs</small>",
            "**True Strength** is the joint filter's estimate of fresh latent 1-rep-max-equivalent capacity. "
            "It is inferred jointly with fatigue from every set and is not forced upward by a per-session gain term. "
            "Units: pounds (lbs)."
        )
    with mcol2:
        metric_with_info(
            "Current Fatigue",
            f"{latest['fatigue']:.1f}",
            "**Fatigue** is a latent state measured in pounds of performance suppression. "
            "It decays according to actual elapsed days, is inferred jointly with strength from set-level performance, "
            "and receives a post-session increment from training dose."
        )
    with mcol3:
        delta = latest['strength'] - results.iloc[0]['strength']
        metric_with_info(
            "Total Gain",
            f"{delta:+.1f} <small>lbs</small>",
            "**Total Gain** is the difference between the current posterior latent-strength estimate and the first-session estimate. "
            "The minimal model does not impose automatic linear progression, so this change is data-driven."
        )
    with mcol4:
        metric_with_info(
            "Sessions",
            f"{len(results)}",
            "**Sessions** is the total number of workouts logged for this lift. "
            "The filter needs at least 3-4 sessions to stabilize; early estimates may be noisy."
        )

    # --- Prediction Card ---
    st.markdown("---")
    st.markdown(f"""
    <div class="prediction-card">
        <div class="metric-label">Next Session Prediction (typical spacing)</div>
        <div class="prediction-main">{pred:.1f} <small>lbs</small></div>
        <div class="prediction-ci">95% Confidence Interval: {ci_low:.1f} — {ci_high:.1f} lbs</div>
    </div>
    """, unsafe_allow_html=True)

    # --- Programming Assistant ---
    programming_assistant(pred)

    # --- Main Chart ---
    st.markdown("---")
    fig = create_dashboard_plot(model, results, selected_lift, projection_weeks)
    st.plotly_chart(fig, use_container_width=True, key="main_chart")

    # --- Expand Graph Button ---
    if st.button("Expand Graph", use_container_width=True):
        show_graph_dialog(model, results, selected_lift, projection_weeks)

    # --- Recent History ---
    with st.expander("Recent Session Details"):
        display_df = results[['date', 'days_since_prior', 'observed', 'predicted', 'residual', 'mean_abs_z', 'stress', 'fatigue', 'strength']].tail(10)
        display_df = display_df.round(2)
        display_df.columns = ['Date', 'Days Since Prior', 'Observed', 'Expected', 'Residual', 'Mean |z|', 'Dose', 'Fatigue (lb)', 'Latent Strength']
        st.dataframe(display_df, use_container_width=True, hide_index=True)


@st.dialog("Strength Trajectory", width="large")
def show_graph_dialog(model: StrengthModel, results_df: pd.DataFrame, lift_name: str, projection_weeks: int):
    """Full-screen dialog for examining the graph. Click outside or press Escape to close."""
    st.caption("Click outside this dialog or press Escape to return.")
    fig = create_dashboard_plot(model, results_df, lift_name, projection_weeks)
    st.plotly_chart(fig, use_container_width=True, height=700)


# =============================================================================
# LOG WORKOUT
# =============================================================================
def page_log_workout(db: Database, user_id: int):
    st.title("Log Workout")
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
        if st.button("Add Set", use_container_width=True):
            st.session_state.num_sets += 1
            st.rerun()
    with c2:
        if st.button("Remove Set", use_container_width=True) and st.session_state.num_sets > 1:
            st.session_state.num_sets -= 1
            st.rerun()

    st.markdown("---")

    preview_sets = [WorkoutSet(w, r, rir) for w, r, rir in set_data]
    est_1rms = [s.estimated_1rm() for s in preview_sets]
    best_idx = int(np.argmax(est_1rms))

    st.markdown("**Estimated 1RMs:** " + ", ".join([f"Set {i+1}: **{e:.1f}** lbs" for i, e in enumerate(est_1rms)]))
    st.markdown(f"**Best estimated 1RM:** Set {best_idx+1} at **{est_1rms[best_idx]:.1f}** lbs")

    if st.button("Save Workout", type="primary", use_container_width=True):
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


# =============================================================================
# HISTORY
# =============================================================================
def page_history(db: Database, user_id: int):
    st.title("Workout History")
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
                if st.button("Delete", key=f"del_{row['id']}"):
                    db.delete_workout(user_id, row['id'])
                    st.rerun()
            st.divider()


# =============================================================================
# EXPORT
# =============================================================================
def page_export(db: Database, user_id: int):
    st.title("Export Data")
    st.caption(f"Logged in as **{st.session_state.username}**")

    lifts = db.get_lifts(user_id)
    if not lifts:
        st.info("No data to export yet.")
        return

    lift_names = {l['name']: l['id'] for l in lifts}
    lift_names["All Lifts"] = None

    selected = st.selectbox("Select Lift to Export", list(lift_names.keys()))
    lift_id = lift_names[selected]

    if st.button("Download Excel", type="primary"):
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
            display = results[['date', 'days_since_prior', 'observed', 'predicted', 'strength', 'fatigue', 'stress', 'strength_ci_95', 'capacity_ci_95']].round(2)
            st.dataframe(display, use_container_width=True, hide_index=True)


# =============================================================================
# SETTINGS
# =============================================================================
def page_settings(db: Database, user_id: int):
    st.title("Settings")
    st.caption(f"Logged in as **{st.session_state.username}**")

    lifts = db.get_lifts(user_id)
    if not lifts:
        st.info("Log at least one lift before saving model parameters.")
    else:
        lift_names = {l['name']: l['id'] for l in lifts}
        selected = st.selectbox("Apply parameters to lift", list(lift_names.keys()))
        lift_id = lift_names[selected]

        current = {**StrengthModel.DEFAULT_PARAMS}
        saved = db.load_params(user_id, lift_id)
        if saved:
            current.update({k: v for k, v in saved.items() if k in current})

        st.markdown("### Model Parameters")
        st.caption("The revised model jointly estimates latent strength and fatigue using actual elapsed time and set-level observations.")

        col1, col2, col3 = st.columns(3)
        with col1:
            rho_day = st.number_input(
                "Daily Fatigue Retention (rho_day)", min_value=0.01, max_value=1.0,
                value=float(current['rho_day']), step=0.05, format="%.2f", key=f"rho_day_{lift_id}",
                help="Fraction of fatigue retained after one day. Recovery over dt days is rho_day^dt."
            )
            b = st.number_input(
                "Dose → Fatigue (b)", min_value=0.0,
                value=float(current['b']), step=0.1, format="%.2f", key=f"b_{lift_id}",
                help="Pounds of next-session performance suppression added per session-dose unit."
            )
            intensity_p = st.number_input(
                "Intensity Exponent (p)", min_value=1.0,
                value=float(current['intensity_p']), step=0.1, format="%.2f", key=f"intensity_p_{lift_id}",
                help="Super-linear weighting of relative intensity in the session-dose equation."
            )
            rir_penalty_c = st.number_input(
                "RIR Dose Penalty (c)", min_value=0.0,
                value=float(current['rir_penalty_c']), step=0.05, format="%.2f", key=f"rir_penalty_c_{lift_id}",
                help="Extra training-dose multiplier for work below the RIR threshold."
            )

        with col2:
            rir_threshold = st.number_input(
                "RIR Threshold (q0)", min_value=0.0, max_value=10.0,
                value=float(current['rir_threshold']), step=1.0, format="%.1f", key=f"rir_threshold_{lift_id}",
                help="Extra dose penalty begins when reported RIR is below this value."
            )
            q_strength_day = st.number_input(
                "Strength Process Variance / Day", min_value=0.0,
                value=float(current['q_strength_day']), step=0.25, format="%.2f", key=f"q_strength_day_{lift_id}",
                help="Random-walk innovation variance for latent strength, in lb²/day."
            )
            q_fatigue_day = st.number_input(
                "Fatigue Process Variance / Day", min_value=0.0,
                value=float(current['q_fatigue_day']), step=0.5, format="%.2f", key=f"q_fatigue_day_{lift_id}",
                help="One-day innovation variance for the exponentially decaying fatigue state, in lb²/day."
            )
            g_per_day = st.number_input(
                "Strength Drift (g, lb/day)",
                value=float(current['g_per_day']), step=0.05, format="%.3f", key=f"g_per_day_{lift_id}",
                help="Default is zero. Later this should be replaced by a training-dependent adaptation model."
            )

        with col3:
            sigma_obs = st.number_input(
                "Baseline Observation SD (lb)", min_value=0.1,
                value=float(current['sigma_obs']), step=0.5, format="%.1f", key=f"sigma_obs_{lift_id}",
                help="Baseline standard deviation of a set-level RIR-adjusted e1RM observation."
            )
            sigma_rir = st.number_input(
                "RIR Uncertainty SD / RIR (lb)", min_value=0.0,
                value=float(current['sigma_rir']), step=0.5, format="%.1f", key=f"sigma_rir_{lift_id}",
                help="Adds observation uncertainty as reported RIR increases."
            )
            robust_z0 = st.number_input(
                "Robustness Threshold |z|", min_value=0.0,
                value=float(current['robust_z0']), step=0.25, format="%.2f", key=f"robust_z0_{lift_id}",
                help="Variance inflation begins when a standardized innovation exceeds this threshold."
            )
            robust_beta = st.number_input(
                "Robustness Inflation (beta)", min_value=0.0,
                value=float(current['robust_beta']), step=0.25, format="%.2f", key=f"robust_beta_{lift_id}",
                help="Controls how sharply observation variance grows beyond the z threshold."
            )
            init_fatigue_sd = st.number_input(
                "Initial Fatigue Uncertainty SD (lb)", min_value=0.1,
                value=float(current['init_fatigue_sd']), step=1.0, format="%.1f", key=f"init_fatigue_sd_{lift_id}",
                help="Uncertainty in how much of first-session capacity reflects fatigue versus fresh strength."
            )

        params = {
            'rho_day': rho_day,
            'b': b,
            'intensity_p': intensity_p,
            'rir_penalty_c': rir_penalty_c,
            'rir_threshold': rir_threshold,
            'q_strength_day': q_strength_day,
            'q_fatigue_day': q_fatigue_day,
            'g_per_day': g_per_day,
            'sigma_obs': sigma_obs,
            'sigma_rir': sigma_rir,
            'robust_z0': robust_z0,
            'robust_beta': robust_beta,
            'init_fatigue_sd': init_fatigue_sd,
        }

        if st.button("Save Parameters", type="primary"):
            db.save_params(user_id, lift_id, params)
            st.success(f"Parameters saved for **{selected}**!")

    st.markdown("---")
    st.markdown("### Demo Data")
    if st.button("Generate Demo Data", help="Creates 12 weeks of Bench Press and 8 weeks of Squat"):
        generate_demo_data(db, user_id)
        st.success("Demo data generated! Go to the Dashboard.")
        st.rerun()

    st.markdown("---")
    st.markdown("### Account")
    if st.button("Sign Out", type="secondary"):
        for key in ['user_id', 'username']:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    **StrengthTracker** now uses a two-state Kalman-style filter:

    - `x = [strength, fatigue]^T`, with a full 2×2 covariance matrix
    - actual elapsed days determine fatigue recovery via `rho_day^Δt`
    - every set is a separate observation of `strength - fatigue`
    - session training dose is applied to fatigue only *after* the session's observations
    - negative residuals are no longer manually assigned to both lower strength and higher fatigue
    - set outliers are handled using standardized-innovation variance inflation
    - the minimal model imposes no automatic strength gain (`g = 0` by default)

    the current RIR-adjusted Brzycki observation and dose equation remain prototypes and should eventually be calibrated from longitudinal data.
    """)


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
        "Dashboard",
        "Log Workout",
        "History",
        "Export",
        "Settings"
    ])

    st.sidebar.markdown("---")

    if page == "Dashboard":
        page_dashboard(db, user_id)
    elif page == "Log Workout":
        page_log_workout(db, user_id)
    elif page == "History":
        page_history(db, user_id)
    elif page == "Export":
        page_export(db, user_id)
    elif page == "Settings":
        page_settings(db, user_id)


if __name__ == "__main__":
    main()
