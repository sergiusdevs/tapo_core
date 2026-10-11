"""Regenerates tests/vectors.json using the python-kasa TPAP implementation.

Needs python-kasa built from https://github.com/python-kasa/python-kasa/pull/1592
(`pip install .` on that checkout). All inputs are fixed and fake, including the
password; no device is contacted. Run from the repository root.
"""
import base64, json, hashlib
from unittest import mock
from ecdsa import NIST256p
from kasa import DeviceConfig
from kasa.transports import tpaptransport as tp

b64 = lambda b: base64.b64encode(b).decode()
G = NIST256p.generator
dev_priv = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF % G.order()
R = dev_priv * G
dev_share = b"\x04" + R.x().to_bytes(32, "big") + R.y().to_bytes(32, "big")
x_fixed = 0x0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C4B5A69788796A5B4C3D2E1F0 % G.order()

user_random = bytes(range(32)); dev_random = bytes(range(100, 132)); salt = bytes(range(16))
password = "test-password-123"
cred = hashlib.sha1(password.encode()).hexdigest()   # password_shadow passwd_id=2
reg = {"dev_random": b64(dev_random), "dev_salt": b64(salt), "dev_share": b64(dev_share),
       "cipher_suites": 1, "iterations": 3000, "encryption": "aes_128_ccm"}

import asyncio
async def main():
    t = tp.TpapTransport(config=DeviceConfig("tpap-host"))
    s = t._encryption_session
    s._user_random = b64(user_random)
    with mock.patch.object(tp.secrets, "randbelow", lambda n: x_fixed - 1):
        share = s._build_share_params_from_register(reg, cred)
    key, nonce = s.key_nonce_from_shared(s._shared_key, "aes_128_ccm", hkdf_hash="SHA256")
    pt = b'{"method":"get_device_info"}'
    ct = s._encrypt_payload("aes_128_ccm", key, nonce, pt, 9)
    out = dict(password=password, credentials_string=cred, register=reg, user_random=b64(user_random),
               x_hex=format(x_fixed, "x"), user_share=share["user_share"], user_confirm=share["user_confirm"],
               expected_dev_confirm=s._expected_dev_confirm, shared_key=b64(s._shared_key),
               key=b64(key), base_nonce=b64(nonce), seq=9, plaintext=pt.decode(), ciphertext_and_tag=b64(ct),
               register_username_md5=hashlib.md5(b"admin").hexdigest())
    json.dump(out, open("tests/vectors.json", "w"), indent=1)
    print({k: (v if len(str(v)) < 60 else str(v)[:40] + "...") for k, v in out.items() if k not in ("register",)})
asyncio.run(main())
