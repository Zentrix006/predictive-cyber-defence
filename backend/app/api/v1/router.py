"""
API v1 Router
"""
from fastapi import APIRouter

from app.api.v1.endpoints import (
    system,
    assets,
    incidents,
    predictions,
    topology,
    deception,
    forensics,
    config,
    analyze,
    enrollment,
    network,
    threats,
    forecast,
    defence,
    model_lab,
    audit,
    simulation,
    reports,
    auth,
    canary,
    discovery_evidence,
    discovery_enrichment,
    graph_topology,
    config_automation,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(predictions.router, prefix="/predictions", tags=["predictions"])
api_router.include_router(topology.router, prefix="/topology", tags=["topology"])
api_router.include_router(deception.router, prefix="/deception", tags=["deception"])
api_router.include_router(forensics.router, prefix="/forensics", tags=["forensics"])
api_router.include_router(config.router, prefix="/config", tags=["config"])
api_router.include_router(analyze.router, prefix="/analyze", tags=["analyze"])
api_router.include_router(enrollment.router, prefix="/enrollment", tags=["enrollment"])
api_router.include_router(network.router, prefix="/network", tags=["network"])
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])
api_router.include_router(forecast.router, prefix="/forecast", tags=["forecast"])
api_router.include_router(defence.router, prefix="/defence", tags=["defence"])
api_router.include_router(model_lab.router, prefix="/model-lab", tags=["model-lab"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(simulation.router, prefix="/simulation", tags=["simulation"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(canary.router, prefix="/canary", tags=["canary"])
api_router.include_router(discovery_evidence.router)
api_router.include_router(discovery_enrichment.router)
api_router.include_router(graph_topology.router)
api_router.include_router(config_automation.router)
api_router.include_router(system.router, prefix="/system", tags=["system"])

