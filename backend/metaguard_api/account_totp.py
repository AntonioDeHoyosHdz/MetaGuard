"""Persistence-only TOTP schema; enrollment and verification are not implemented."""

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from metaguard_api.database import Base


class AccountTotp(Base):
    __tablename__ = "account_totp"
    __table_args__ = (
        CheckConstraint(
            "length(encrypted_secret) BETWEEN 30 AND 1053", name="ck_totp_secret_length"
        ),
        CheckConstraint("key_version > 0", name="ck_totp_key_version"),
        CheckConstraint(
            "last_accepted_step IS NULL OR last_accepted_step >= 0", name="ck_totp_step"
        ),
    )

    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    last_accepted_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
