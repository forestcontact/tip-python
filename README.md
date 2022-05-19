### Versions:

 * go version go1.18.2 linux/amd64
 * Python 3.9.12

### Installation:

```bash
pipenv install
cd src/tip/ && go build -o libtip.a -buildmode=c-archive && cd ..
pipenv run python3 setup.py bdist_wheel
```

### Key derivation (ephemeral)

Pin is 123456

Identity seed (Si) (from centralized database) is `2e613...8f`

use ie) [argon2-cffi](https://pypi.org/project/argon2-cffi)
```python3
# from a user
PIN = b"123456"
# from a centralized database
identity_seed = S_i = b"2e613adae4f0167255933a3ec1d97e0acdd38e46d319c348b7a3d709f23bae8f"
# combined to form a cryptographic identity provided to the TIP client as the private key for the throttled signing requests
identity = argon2.low_level.hash_secret_raw(PIN, S_i, 1024, 256*1024, 4, 64, argon2.Type.ID)
# passed as the ephemeral value
```

### References 

 * https://tip.id
 * https://github.com/MixinNetwork/tip/tree/main/signer
 * https://en.wikipedia.org/wiki/BLS_digital_signature


### To test:

ephemeral is strong-hash of PIN and central account identifier
current timestamp is used as nonce by default
default invocation generates a new key for each run

```fish
python3 -m tip.app -c config.json sign --key (python3 -m tip.app -c config.json key | head -n 1) --ephemeral 5180bca3d830c41f62e4a9440a23fa82
```

### To rebuild:

```bash
pipenv run pip3 uninstall tip && python3 setup.py clean && python3 setup.py bdist_wheel && pipenv run pip3 install dist/tip-0.3.0-cp39-cp39-linux_x86_64.whl
```
