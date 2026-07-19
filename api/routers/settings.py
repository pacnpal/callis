from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import (
    CONFIGURABLE_SETTINGS,
    get_db,
    get_effective_settings,
    load_db_settings,
    update_db_settings_cache,
    write_audit_log,
)
from dependencies import require_role
from models import AuditAction, Setting, User
from schemas import SettingFieldOut, SettingsOut

router = APIRouter(prefix="/settings")


def _setting_fields(current_values: dict) -> list[SettingFieldOut]:
    """Flatten CONFIGURABLE_SETTINGS metadata + effective values, preserving order."""
    fields: list[SettingFieldOut] = []
    for key, meta in CONFIGURABLE_SETTINGS.items():
        fields.append(
            SettingFieldOut(
                key=key,
                label=meta["label"],
                help=meta["help"],
                type=meta["type"],
                value=current_values.get(key, meta["default"]),
                group=meta["group"],
                choices=meta.get("choices"),
                min=meta.get("min"),
                max=meta.get("max"),
                readonly=bool(meta.get("readonly")),
            )
        )
    return fields


def _installer_url(current_values: dict) -> str:
    """Return the CLI installer URL based on the effective base_url setting."""
    default_base_url = "http://localhost:8080"
    configured_base_url = str(current_values.get("base_url", default_base_url))
    parsed_base_url = urlparse(configured_base_url)

    if parsed_base_url.scheme and parsed_base_url.netloc:
        base_url = f"{parsed_base_url.scheme}://{parsed_base_url.netloc}"
    else:
        base_url = default_base_url
    return f"{base_url}/install.sh"


@router.get("")
async def settings_page(
    user: User = Depends(require_role("admin")),
) -> SettingsOut:
    db_settings = await load_db_settings()
    current = get_effective_settings(db_settings)
    return SettingsOut(fields=_setting_fields(current), installer_url=_installer_url(current))


@router.put("")
async def save_settings(
    request: Request,
    body: dict[str, str],
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> SettingsOut:
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
    reverted_to: dict[str, str] = {}     # key -> effective value after revert

    for key, meta in CONFIGURABLE_SETTINGS.items():
        if meta.get("readonly"):
            continue

        submitted = body.get(key, "")
        raw = submitted if meta["type"] == "text" else submitted.strip()

        # For string-like settings, an empty submission removes the DB override
        # so the env-var / compiled default takes effect again. Empty numeric
        # submissions revert the same way.
        if not raw and meta["type"] in {"str", "text", "int"}:
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
        raise HTTPException(status_code=400, detail="; ".join(validation_errors))

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
    # Update the in-memory cache directly with the committed mutations so
    # concurrent requests never repopulate it from stale pre-commit DB state.
    update_db_settings_cache(pending_upserts, pending_deletes)

    # Build the post-save view in memory from the validated changes so we
    # don't need a redundant DB round-trip after the explicit commit above.
    current_values = dict(old_values)
    for key in pending_deletes:
        current_values[key] = reverted_to[key]
    for key, new_value in pending_upserts.items():
        current_values[key] = new_value

    return SettingsOut(
        fields=_setting_fields(current_values),
        installer_url=_installer_url(current_values),
    )
