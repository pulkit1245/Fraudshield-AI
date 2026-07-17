"""Novelty / repacked-variant detection via reconstruction error.

Trains on benign feature vectors; a sample whose reconstruction error exceeds the
benign distribution is flagged as novel — catching repacked/obfuscated variants
that no hash match would find.

Two backends behind one `NoveltyDetector` API:
  - "torch": a real PyTorch autoencoder (§2 stack) — used when torch is installed.
  - "pca":   a scikit-learn PCA reconstruction fallback — fully offline default,
             so the pipeline runs with no heavyweight DL dependency.

Both expose the same `fit()` / `score()` and both measure reconstruction error,
so the ensemble treats them identically.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import numpy as np

from app.core.logging import get_logger
from app.ml.feature_spec import N_FEATURES

log = get_logger(__name__)


def build_torch_autoencoder(n_features: int, latent: int = 8):
    """Construct a PyTorch autoencoder module (lazy import). Raises if torch absent."""
    import torch.nn as nn  # noqa: WPS433

    class FeatureAutoencoder(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(n_features, 32), nn.ReLU(),
                nn.Linear(32, 16), nn.ReLU(),
                nn.Linear(16, latent), nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent, 16), nn.ReLU(),
                nn.Linear(16, 32), nn.ReLU(),
                nn.Linear(32, n_features),
            )

        def forward(self, x):
            return self.decoder(self.encoder(x))

    return FeatureAutoencoder()


class NoveltyDetector:
    def __init__(self, backend: str = "auto", n_features: int = N_FEATURES) -> None:
        self.n_features = n_features
        self.backend = self._resolve_backend(backend)
        self._fitted = False
        self._scaler_mean: np.ndarray | None = None
        self._scaler_std: np.ndarray | None = None
        self._pca = None
        self._torch_model = None
        self._err_median = 0.0
        self._err_scale = 1.0

    @staticmethod
    def _resolve_backend(backend: str) -> str:
        if backend != "auto":
            return backend
        try:
            import torch  # noqa: F401
            return "torch"
        except Exception:  # noqa: BLE001
            return "pca"

    # ── fit ─────────────────────────────────────────────────────────────
    def fit(self, X_benign: np.ndarray) -> "NoveltyDetector":
        X = np.asarray(X_benign, dtype=np.float64)
        self._scaler_mean = X.mean(axis=0)
        self._scaler_std = X.std(axis=0) + 1e-8
        Xs = (X - self._scaler_mean) / self._scaler_std

        if self.backend == "torch":
            self._fit_torch(Xs)
        else:
            self._fit_pca(Xs)

        errors = np.array([self._recon_error(x) for x in Xs])
        self._err_median = float(np.median(errors))
        self._err_scale = float(np.median(np.abs(errors - self._err_median)) + 1e-6)
        self._fitted = True
        log.info("novelty.fitted", backend=self.backend, ref_median=round(self._err_median, 4))
        return self

    def _fit_pca(self, Xs: np.ndarray) -> None:
        from sklearn.decomposition import PCA

        k = max(2, min(self.n_features // 2, Xs.shape[0] - 1, 12))
        self._pca = PCA(n_components=k, random_state=42).fit(Xs)

    def _fit_torch(self, Xs: np.ndarray) -> None:  # pragma: no cover - needs torch
        import torch

        model = build_torch_autoencoder(self.n_features)
        opt = torch.optim.Adam(model.parameters(), lr=1e-3)
        loss_fn = torch.nn.MSELoss()
        data = torch.tensor(Xs, dtype=torch.float32)
        model.train()
        for _ in range(60):
            opt.zero_grad()
            out = model(data)
            loss = loss_fn(out, data)
            loss.backward()
            opt.step()
        model.eval()
        self._torch_model = model

    # ── scoring ─────────────────────────────────────────────────────────
    def _recon_error(self, xs_row: np.ndarray) -> float:
        if self.backend == "torch" and self._torch_model is not None:  # pragma: no cover
            import torch

            with torch.no_grad():
                t = torch.tensor(xs_row.reshape(1, -1), dtype=torch.float32)
                recon = self._torch_model(t).numpy().ravel()
        elif self._pca is not None:
            recon = self._pca.inverse_transform(self._pca.transform(xs_row.reshape(1, -1))).ravel()
        else:
            return 0.0
        return float(np.mean((xs_row - recon) ** 2))

    def score(self, vector: np.ndarray) -> float:
        """Return normalized novelty in [0, 1] (higher = more anomalous)."""
        if not self._fitted:
            self.fit(_benign_reference())
        x = np.asarray(vector, dtype=np.float64)
        xs = (x - self._scaler_mean) / self._scaler_std
        err = self._recon_error(xs)
        # Robust z against the benign error distribution
        z = (err - self._err_median) / (self._err_scale * 3.0)
        if z <= 0.0:
            return 0.0
        # For error above median, map to [0, 1) smoothly.
        return float(1.0 - np.exp(-z))


# ── lazily-fitted process-wide default ──────────────────────────────────
_default: NoveltyDetector | None = None


def _benign_reference(n: int = 600) -> np.ndarray:
    """Synthetic benign reference set (mirrors train.py's benign class)."""
    from app.ml.classifier.train import _make_finding
    from app.ml.feature_spec import featurize

    rng = np.random.default_rng(7)
    rows = []
    for _ in range(n):
        static, dynamic = _make_finding(rng, fraud=False)
        rows.append(featurize(static, dynamic))
    return np.vstack(rows)


def get_default_detector() -> NoveltyDetector:
    global _default
    if _default is None:
        _default = NoveltyDetector(backend="auto").fit(_benign_reference())
    return _default


def novelty_score(vector: np.ndarray) -> float:
    return get_default_detector().score(vector)
