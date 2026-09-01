"""Declarative base shared by all ORM models (docs/DATA_MODEL.md §1)."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
