import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.core.config import settings

_PRIVATE_KEY_FILENAME = "shadowtrace_signing_private.pem"
_PUBLIC_KEY_FILENAME = "shadowtrace_signing_public.pem"


def _key_dir() -> Path:
    return Path.cwd() / settings.signing_key_dir


def _private_key_path() -> Path:
    return _key_dir() / _PRIVATE_KEY_FILENAME


def _public_key_path() -> Path:
    return _key_dir() / _PUBLIC_KEY_FILENAME


def _ensure_keypair() -> None:
    key_directory = _key_dir()
    key_directory.mkdir(parents=True, exist_ok=True)

    private_key_path = _private_key_path()
    public_key_path = _public_key_path()
    if private_key_path.exists() and public_key_path.exists():
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _load_private_key():
    _ensure_keypair()
    return serialization.load_pem_private_key(_private_key_path().read_bytes(), password=None)


def get_public_key_pem() -> str:
    _ensure_keypair()
    return _public_key_path().read_text(encoding="utf-8")


def sign_payload(payload: bytes) -> str:
    private_key = _load_private_key()
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")
