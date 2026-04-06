from collections import OrderedDict

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import (
    CONFIGURABLE_SETTINGS,
    get_db,
    get_effective_settings,
    invalidate_db_settings_cache,
    load_db_settings,
    register_template_filters,
    write_audit_log,
)
from dependencies import require_role
from models import AuditAction, Setting, User

router = APIRouter()
templates = Jinja2Templates(directory="templates")
register_template_filters(templates)


def _grouped_settings(current_values: dict) -> OrderedDict:
    """Group settings by their group label, preserving order."""
    groups: OrderedDict[str, list] = OrderedDict()
    for key, meta in CONFIGURABLE_SETTINGS.items():
        group = meta["group"]
        if group not in groups:
            groups[group] = []
        groups[group].append({**meta, "key": key, "value": current_values.get(key, meta["default"])})
    return groups


@router.get("/settings")
async def settings_page(
    request: Request,
    user: User = Depends(require_role("admin")),
):
    db_settings = await load_db_settings()
    current = get_effective_settings(db_settings)
    groups = _grouped_settings(current)

    return templates.TemplateResponse(
        request,
        "settings.html",
        context={"user": user, "groups": groups},
    )


@router.post("/settings")
async def save_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    form = await request.form()
    db_settings = await load_db_settings()
    old_values = get_effective_settings(db_settings)
    changes: dict[str, dict] = {}

    for key, meta in CONFIGURABLE_SETTINGS.items():
        if meta.get("readonly"):
            continue

        submitted = form.get(key, "")
        raw = submitted if meta["type"] == "text" else submitted.strip()
        if not raw and meta["type"] in ("int",):
            continue  # skip empty numeric fields

        # Validate and convert
        if meta["type"] == "int":
            try:
                val = int(raw)
            except ValueError:
                continue
            min_val = meta.get("min")
            max_val = meta.get("max")
            if min_val is not None and val < min_val:
                val = min_val
            if max_val is not None and val > max_val:
                val = max_val
            new_value = str(val)
        elif meta["type"] == "choice":
            if raw not in meta.get("choices", []):
                continue
            new_value = raw
        else:
            new_value = raw

        old_val = str(old_values.get(key, meta["default"]))
        if new_value != old_val:
            changes[key] = {"old": old_val, "new": new_value}

        # Upsert into DB
        existing = await db.execute(select(Setting).where(Setting.key == key))
        setting = existing.scalar_one_or_none()
        if setting:
            setting.value = new_value
        else:
            db.add(Setting(key=key, value=new_value))

    if changes:
        await write_audit_log(
            db,
            actor_id=user.id,
            action=AuditAction.SETTINGS_CHANGED,
            target_type="settings",
            source_ip=request.client.host if request.client else None,
            detail=changes,
        )

    await db.flush()
    await db.commit()
    invalidate_db_settings_cache()

    return templates.TemplateResponse(
        request,
        "settings.html",
        context={
            "user": user,
            "groups": _grouped_settings(get_effective_settings(
                {s.key: s.value for s in (await db.execute(select(Setting))).scalars().all()}
            )),
            "success": "Settings saved." if changes else "No changes detected.",
        },
    )
