import os
import tempfile

# Must be set before core is imported: gives tests a stable SECRET_KEY and a
# private secret-key file location, so nothing collides with a real /data
# volume on the machine running the tests.
os.environ["SECRET_KEY"] = "a" * 64
os.environ["CALLIS_SECRET_KEY_FILE"] = os.path.join(
    tempfile.mkdtemp(prefix="callis-test-"), ".secret_key"
)
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
