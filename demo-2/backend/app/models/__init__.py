from app.models.demo import (  # noqa: F401
    DemoAsset,
    Participant,
    DemoIncident,
    Challenge,
    DemoEvent,
    PredictionRecord,
    DecoyInteraction,
    EvidenceRecord,
    AssetStatus,
    AssetRole,
    ParticipantRole,
    IncidentStatus,
)
from app.core.database import Base

MODELS = [
    DemoAsset, Participant, DemoIncident, Challenge,
    DemoEvent, PredictionRecord, DecoyInteraction, EvidenceRecord,
]