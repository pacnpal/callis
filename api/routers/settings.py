from collections import OrderedDict
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import (
    CONFIGURABLE_SETTINGS,
    get_db,
    get_effective_settings,
    load_db_settings,
    register_template_filters,
    update_db_settings_cache,
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
    validation_errors: list[str] = []

    # Preload all existing settings in a single query to avoid N+1
    existing_result = await db.execute(select(Setting))
    existing_map: dict[str, Setting] = {s.key: s for s in existing_result.scalars().all()}

    # First pass: validate every submitted value without touching the DB.
    # Collect pending mutations and any errors atomically.
    pending_deletes: list[str] = []      # keys whose DB rows should be removed
    pending_upserts: dict[str, str] = {} # key -> validated new_value to write
    changes: dict[str, dict] = {}
    reverted_to: dict[str, str] = {}     # key -> effective value after revert (for form render)

    for key, meta in CONFIGURABLE_SETTINGS.items():
        if meta.get("readonly"):
            continue

        submitted = form.get(key, "")
        raw = submitted if meta["type"] == "text" else submitted.strip()

        # For string-like settings, an empty submission removes the DB override
        # so the env-var / compiled default takes effect again.
        if meta["type"] in {"str", "text"} and not raw:
            if key in existing_map:
                old_val = str(old_values.get(key, meta["default"]))
                new_effective = str(get_effective_settings({}).get(key, meta["default"]))
                changes[key] = {"old": old_val, "new": f"(reverted to: {new_effective})"}
                pending_deletes.append(key)
                reverted_to[key] = new_effective
            continue

        if not raw and meta["type"] == "int":
            # Empty numeric submission: remove DB override to revert to env/default,
            # same semantics as clearing a string field.
            if key in existing_map:
                old_val = str(old_values.get(key, meta["default"]))
                new_effective = str(get_effective_settings({}).get(key, meta["default"]))
                changes[key] = {"old": old_val, "new": f"(reverted to: {new_effective})"}
                pending_deletes.append(key)
                reverted_to[key] = new_effective
            continue

        # Validate and convert
        if meta["type"] == "int":
            try:
                val = int(raw)
            except ValueError:
                validation_errors.append(f"'{meta['label']}' must be a valid integer")
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
                validation_errors.append(f"'{meta['label']}' has invalid value '{raw}'")
                continue
            new_value = raw
        else:
            # Validate URL-typed settings require a scheme and hostname.
            if key == "base_url":
                if not raw.startswith(("http://", "https://")):
                    validation_errors.append(
                        f"'{meta['label']}' must start with http:// or https://"
                    )
                    continue
                parsed = urlparse(raw)
                if not parsed.hostname:
                    validation_errors.append(
                        f"'{meta['label']}' must include a valid hostname"
                    )
                    continue
            new_value = raw

        old_val = str(old_values.get(key, meta["default"]))
        if new_value != old_val:
            changes[key] = {"old": old_val, "new": new_value}
            pending_upserts[key] = new_value

    # If any field failed validation, return errors without persisting anything.
    if validation_errors:
        return templates.TemplateResponse(
            request,
            "settings.html",
            context={
                "user": user,
                "groups": _grouped_settings(old_values),
                "error": "; ".join(validation_errors),
            },
            status_code=400,
        )

    # Second pass: apply all validated changes atomically.
    for key in pending_deletes:
        await db.delete(existing_map[key])
    for key, new_value in pending_upserts.items():
        setting = existing_map.get(key)
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
            detail={k: f"{v['old']} → {v['new']}" for k, v in changes.items()},
        )

    await db.flush()
    # Commit the transaction first so the cache is only updated after the
    # data has actually persisted.  If the commit raises, the exception
    # propagates to get_db()'s teardown which handles rollback; the cache
    # update below is never reached, so it never reflects unpersisted values.
    await db.commit()
    # Update the in-memory cache directly with the committed mutations so that:
    # (a) this response's template render sees the new instance_name / values,
    # (b) there is no window where the cache is None and a concurrent request
    #     can repopulate it with pre-commit (stale) data from the DB.
    update_db_settings_cache(pending_upserts, pending_deletes)

    # Build the post-save view in memory from the validated changes so we
    # don't need a redundant DB round-trip after the explicit commit above.
    current_values = dict(old_values)
    for key in pending_deletes:
        current_values[key] = reverted_to[key]
    for key, new_value in pending_upserts.items():
        current_values[key] = new_value

    return templates.TemplateResponse(
        request,
        "settings.html",
        context={
            "user": user,
            "groups": _grouped_settings(current_values),
            "success": "Settings saved." if changes else "No changes detected.",
        },
    )
