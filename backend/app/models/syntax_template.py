from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, UniqueConstraint
from app.models.base import Base

class VendorSyntaxTemplate(Base):
    __tablename__ = "vendor_syntax_templates"
    id = Column(Integer, primary_key=True, index=True)
    vendor = Column(String, index=True, nullable=False)
    os_version = Column(String, index=True, nullable=False)
    abstract_intent = Column(String, index=True, nullable=False)
    syntax_template = Column(Text, nullable=False)
    # Templates are untrusted research output until reviewed and verified.
    status = Column(String, nullable=False, default="candidate", index=True)
    source_url = Column(Text, nullable=True)
    source_hash = Column(String(64), nullable=True)
    evidence_ref = Column(Text, nullable=True)
    confidence = Column(Float, nullable=False, default=0.0)
    generated_by = Column(String, nullable=False, default="offline_fixture")
    created_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("vendor", "os_version", "abstract_intent", name="uix_vendor_os_intent"),
    )
