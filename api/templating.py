"""Shared Jinja2 template environment.

Single source of truth for template rendering: one Templates instance with
the custom filters/globals registered exactly once. Import `templates` from
here instead of constructing a new Jinja2Templates per module.
"""

from fastapi.templating import Jinja2Templates

from core import register_template_filters

templates = Jinja2Templates(directory="templates")
register_template_filters(templates)
