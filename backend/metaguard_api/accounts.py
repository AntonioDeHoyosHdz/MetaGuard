"""Private account persistence schema; no registration or authentication endpoints."""

from sqlalchemy import CheckConstraint, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from metaguard_api.database import Base


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        CheckConstraint("length(email) BETWEEN 3 AND 254", name="ck_accounts_email_length"),
        CheckConstraint("email = lower(email)", name="ck_accounts_email_lowercase"),
        UniqueConstraint("email", name="uq_accounts_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
