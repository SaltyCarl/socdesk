import pytest
from tools.picket.fence import MAX_CRED_LEN, MIN_CRED_HITS, fence_credential, is_public_ip


@pytest.mark.parametrize("value", ["admin", "root", "123456", "P@ssw0rd!", "ubuntu"])
def test_common_credentials_pass(value):
    assert fence_credential(value) == value


@pytest.mark.parametrize("value", [
    "alice@example.com",            # email
    "bob@corp",                     # any '@' — could be a real account handle
    "+1 415 555 0199",              # phone-like digit run
    "4111 1111 1111 1111",          # card-like
    "123-45-6789 extra",            # SSN-like run inside a longer string
    "x" * (MAX_CRED_LEN + 1),       # over length
    "",                             # empty
    "   ",                          # whitespace only
])
def test_fenced_values_are_dropped(value):
    assert fence_credential(value) is None


def test_markup_is_stripped_not_dropped():
    # clean_text reduces markup to inert text; a bot really does try such strings
    assert fence_credential("<b>admin</b>") == "admin"
    assert fence_credential("<img src=x onerror=alert(1)//") == "img src=x onerror=alert(1)//"


def test_constants():
    assert MAX_CRED_LEN == 32 and MIN_CRED_HITS == 3


@pytest.mark.parametrize("ip,ok", [
    ("8.8.8.8", True), ("2001:4860:4860::8888", True),
    ("10.0.0.1", False), ("192.168.1.1", False), ("172.16.0.1", False),
    ("127.0.0.1", False), ("169.254.1.1", False), ("::1", False), ("fc00::1", False),
    ("not-an-ip", False), ("8.8.8.0/24", False),
])
def test_is_public_ip(ip, ok):
    assert is_public_ip(ip) is ok
