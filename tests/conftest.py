import shutil
from datetime import datetime, timedelta
import multiprocessing
import os
from pathlib import Path
import time
from uuid import UUID

import mse_lib_sgx.http_server
from mse_lib_sgx.certificate import Certificate
import mse_lib_sgx.globs as globs
import pytest


@pytest.fixture(scope="session")
def set_env(tmp_path_factory) -> None:
    home_dir_path = tmp_path_factory.mktemp("home")
    key_dir_path = tmp_path_factory.mktemp("key")
    module_dir_path = tmp_path_factory.mktemp("mse-app")

    os.environ["HOME"] = f"{home_dir_path}"
    os.environ["KEY_PATH"] = f"{key_dir_path}"
    os.environ["MODULE_PATH"] = f"{module_dir_path}"


@pytest.fixture(scope="module")
def home_dir_path() -> Path:
    return Path(os.environ["HOME"]).resolve()


@pytest.fixture(scope="module")
def key_dir_path() -> Path:
    return Path(os.environ["KEY_PATH"]).resolve()


@pytest.fixture(scope="module")
def module_dir_path() -> Path:
    return Path(os.environ["MODULE_PATH"]).resolve()


@pytest.fixture(scope="module")
def test_dir_path() -> Path:
    return Path(__file__).parent.resolve()


@pytest.fixture(scope="module")
def app_dir_path(tmp_path_factory, test_dir_path) -> Path:
    file_path = test_dir_path / "data" / "app.py.enc"
    app_dir_path = tmp_path_factory.mktemp("encrypted-app")
    shutil.copy2(file_path, app_dir_path)

    return app_dir_path


@pytest.fixture(scope="module")
def code_secret_key(test_dir_path) -> bytes:
    return (test_dir_path / "data" / "code.key").read_bytes()


@pytest.fixture(scope="module")
def application() -> str:
    return "app:x"


@pytest.fixture(scope="module")
def host() -> str:
    return "127.0.0.1"


@pytest.fixture(scope="module")
def port() -> int:
    return 8080


@pytest.fixture(scope="module")
def uuid() -> UUID:
    return UUID("00000000-0000-0000-0000-000000000000")


@pytest.fixture(scope="module")
def certificate(key_dir_path):
    expiration_date = datetime.now() + timedelta(hours=10)

    return Certificate(
        enclave_id="test",
        subject_alternative_name="localhost",
        subject=globs.SUBJECT,
        root_path=key_dir_path,
        expiration_date=expiration_date,
        ratls=None,
    )


@pytest.fixture(scope="module")
def conf_server(host, port, uuid, certificate):
    proc = multiprocessing.Process(
        target=mse_lib_sgx.http_server.serve,
        args=(host, port, certificate, uuid, False, 10),
    )
    proc.start()
    time.sleep(1)
    yield proc
    proc.terminate()


@pytest.fixture(scope="module")
def conf_server_low_timeout(host, port, uuid, certificate):
    proc = multiprocessing.Process(
        target=mse_lib_sgx.http_server.serve,
        args=(host, port, certificate, uuid, False, 1),
    )
    proc.start()
    time.sleep(1)
    yield proc
    proc.terminate()
