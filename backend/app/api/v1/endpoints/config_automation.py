"""
Configuration Automation & Rollback Watchdog Endpoints (Phase 5).
Exposes Mode D (Planning) and Mode E (Canary Watchdog) automation capabilities.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_current_user
from app.schemas.config_automation import (
    ConfigPlanRequest,
    ConfigPlanResponse,
    CanaryExecutionRequest,
    CanaryExecutionResponse,
    WatchdogStatusResponse,
)
from app.services.config_automation import (
    ConfigPlanningEngine,
    RollbackWatchdogEngine,
    VaultSecretResolver,
)

router = APIRouter(prefix="/automation", tags=["config-automation"])


@router.post("/plan", response_model=ConfigPlanResponse)
async def compile_config_plan(
    req: ConfigPlanRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Mode D: Pre-flight Configuration Planning.
    Compiles vendor CLI/YANG commands, executes safety inspection, and generates unified syntax diff.
    """
    try:
        # Validate vault reference format if supplied
        VaultSecretResolver.resolve_credential_ref(req.vault_ref)
        plan = ConfigPlanningEngine.build_plan(req)
        return plan
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Planning failed: {str(e)}")


@router.post("/canary/execute", response_model=CanaryExecutionResponse, status_code=201)
async def execute_canary_change(
    req: CanaryExecutionRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Mode E: Canary Configuration Execution with 60-Second Rollback Watchdog.
    Arms watchdog timer. If unconfirmed or health drops, executes automated sub-second rollback.
    """
    try:
        roles = set(current_user.get("roles", [])) if isinstance(current_user, dict) else set()
        if isinstance(current_user, dict) and current_user.get("role"):
            roles.add(str(current_user["role"]))
        if not current_user.get("elevated") and not roles.intersection({"admin", "operator"}):
            raise HTTPException(status_code=403, detail="Elevated operator approval is required for configuration execution")
        if not req.plan_id.startswith("plan_"):
            raise HTTPException(status_code=400, detail="Only validated configuration plans may be executed")
        if len(req.operations) > 100 or any("\n" in op or "\r" in op for op in req.operations):
            raise HTTPException(status_code=400, detail="Invalid configuration operation payload")
        operator_id = current_user.get("sub", req.operator_id) if isinstance(current_user, dict) else req.operator_id
        req.operator_id = operator_id
        response = await RollbackWatchdogEngine.arm_canary_watchdog(req)
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Canary execution failed: {str(e)}")


@router.post("/watchdog/{task_id}/confirm", response_model=WatchdogStatusResponse)
async def confirm_canary_success(
    task_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Operator confirmation: verifies change is operating nominally and permanently commits configuration,
    disarming the 60-second rollback watchdog.
    """
    try:
        operator_id = current_user.get("sub", "operator") if isinstance(current_user, dict) else "operator"
        result = await RollbackWatchdogEngine.confirm_watchdog(task_id, operator_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Confirmation failed: {str(e)}")


@router.post("/watchdog/{task_id}/rollback", response_model=WatchdogStatusResponse)
async def trigger_manual_rollback(
    task_id: str,
    reason: str = Query("manual_soc_operator_override"),
    current_user: dict = Depends(get_current_user),
):
    """
    Operator manual rollback trigger: executes pre-compiled reverse rollback operations in <1 second.
    """
    try:
        result = await RollbackWatchdogEngine.trigger_rollback(task_id, reason=reason)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rollback failed: {str(e)}")


@router.get("/watchdog/status", response_model=List[WatchdogStatusResponse])
async def list_active_watchdogs(
    current_user: dict = Depends(get_current_user),
):
    """
    Query all active and recent canary rollback watchdog timers.
    """
    return RollbackWatchdogEngine.list_watchdogs()


@router.get("/watchdog/{task_id}", response_model=WatchdogStatusResponse)
async def get_watchdog_status(
    task_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Query status and remaining seconds for a specific canary rollback watchdog.
    """
    status = RollbackWatchdogEngine.get_status(task_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Watchdog task {task_id} not found")
    return status
