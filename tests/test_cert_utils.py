from mse_lib_sgx.certificate import to_wildcard_domain


def test_wildcard():
    assert to_wildcard_domain("localhost") == "localhost"
    assert to_wildcard_domain("127.0.0.1") == "127.0.0.1"
    assert to_wildcard_domain("cosmian.app") == "cosmian.app"
    assert to_wildcard_domain(".cosmian.app") == "*.cosmian.app"
    assert (
        to_wildcard_domain("9a5029d5-f769-4749-804e-50f6711bd509.cosmian.app")
        == "*.cosmian.app"
    )
    assert (
        to_wildcard_domain("9a5029d5-f769-4749-804e-50f6711bd509.dev.cosmian.app")
        == "*.dev.cosmian.app"
    )
    assert (
        to_wildcard_domain("9a5029d5-f769-4749-804e-50f6711bd509.staging.cosmian.app")
        == "*.staging.cosmian.app"
    )
