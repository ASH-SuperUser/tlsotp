# TLSOTP

> **T**ime **L**ocation **S**tring **O**ne-**T**ime **P**assword


## Project Links

* GitHub: [https://github.com/ASH-SuperUser/tlsotp](https://github.com/ASH-SuperUser/tlsotp)
* PyPI: [https://pypi.org/project/tlsotp/](https://pypi.org/project/tlsotp/)


## Installation

### 1. Standard Installation (Recommended)

Install the latest stable release from PyPI:

```bash
pip install tlsotp
```

---

### 2. Development Installation (Editable Mode)

Use this if you want to modify the source code locally:

```bash
pip install -e .[dev]
```

This installs:

* pytest
* hypothesis
* editable local package (`src/` changes reflect immediately)

---

### 3. GitHub Installation (Normal)

Install directly from the main branch:

```bash
pip install git+https://github.com/ASH-SuperUser/tlsotp.git
```

---

### 4. GitHub Development Installation (Editable from Source)

Clone and install in editable mode:

```bash
git clone https://github.com/ASH-SuperUser/tlsotp.git
cd tlsotp
pip install -e .[dev]
```

---

### 5. Verification

Check installation:

```bash
python -c "import tlsotp; print(tlsotp.__version__)"
```


## License

This project is licensed under the **Apache License 2.0**.

You are free to use, modify, and distribute it under the terms of the license.

```LICENCE
Copyright 2026 ASH-SuperUser

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## :warning: Disclaimer

!!! warning "TLSOTP Useage Warning"

    TLSOTP is provided **as-is**.
    The author is not responsible for any kind of damage or data loss

!!! warning "TLSOTP Data Loss Warning"

    Once Key is Lost there is no way to get the correct OTP

The author is not responsible for:

* Security misuse
* Data loss
* System failures
* Incorrect implementation

Use responsibly.
