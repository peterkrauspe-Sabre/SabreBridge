from __future__ import annotations
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

def setup_rotating_logger(path: Path, level=logging.INFO, name: str = None) -> logging.Logger:
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name or path.stem)
    logger.setLevel(level)
    # Avoid duplicate handlers if called twice
    if any(isinstance(h, RotatingFileHandler) and getattr(h, "_sabre_path", None) == str(path) for h in logger.handlers):
        return logger
    handler = RotatingFileHandler(str(path), maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    setattr(handler, "_sabre_path", str(path))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    # Also useful to see errors in console while developing
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.setLevel(level)
        logger.addHandler(sh)
    return logger
