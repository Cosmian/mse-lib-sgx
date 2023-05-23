import importlib
import json
import ssl
import sys
import time
import urllib.request

import pytest
from mse_lib_crypto.xsalsa20_poly1305 import decrypt_directory


def test_bad_uuid(
    set_env,
    code_secret_key,
    host,
    port,
    conf_server,
):
    assert conf_server.is_alive()

    uuid = "64260dd9-57dd-47a1-8fd4-9992b4d12213"
    req = urllib.request.Request(
        url=f"https://{host}:{port}", headers={"Content-Type": "application/json"}
    )
    data: bytes = json.dumps(
        {"uuid": str(uuid), "code_secret_key": code_secret_key.hex()}
    ).encode("utf-8")
    req.add_header("Content-Length", str(len(data)))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(req, data, context=ctx)


def test_no_uuid(
    set_env,
    code_secret_key,
    host,
    port,
    conf_server,
):
    assert conf_server.is_alive()

    req = urllib.request.Request(
        url=f"https://{host}:{port}", headers={"Content-Type": "application/json"}
    )
    data: bytes = json.dumps({"code_secret_key": code_secret_key.hex()}).encode("utf-8")
    req.add_header("Content-Length", str(len(data)))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(req, data, context=ctx)


def test_good_flow(
    set_env,
    app_dir_path,
    key_dir_path,
    module_dir_path,
    code_secret_key,
    host,
    port,
    uuid,
    conf_server,
):
    req = urllib.request.Request(
        url=f"https://{host}:{port}", headers={"Content-Type": "application/json"}
    )
    data: bytes = json.dumps(
        {"uuid": str(uuid), "code_secret_key": code_secret_key.hex()}
    ).encode("utf-8")
    req.add_header("Content-Length", str(len(data)))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    assert conf_server.is_alive()
    response = urllib.request.urlopen(req, data, context=ctx)
    assert response.status == 200

    time.sleep(2)
    assert conf_server.is_alive() is False

    decrypt_directory(
        dir_path=app_dir_path,
        key=code_secret_key,
        ext=".enc",
        out_dir_path=module_dir_path,
    )
    (key_dir_path / "code.key").write_bytes(code_secret_key)

    sys.path.append(f"{module_dir_path}")

    module = importlib.import_module("app")

    assert getattr(module, "x") == 1
    assert getattr(module, "y") == 2
    assert getattr(module, "z") == 3


def test_timeout(
    set_env,
    conf_server_low_timeout,
):
    assert conf_server_low_timeout.is_alive()
    time.sleep(1.2)
    assert conf_server_low_timeout.is_alive() is False
