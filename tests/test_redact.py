"""Secrets never reach an LLM: masking in every prompt, and secret findings / files are never sent."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secreview.config import Config                       # noqa: E402
from secreview.ground import llm_ground                    # noqa: E402
from secreview.llm.base import LLMClient, LLMError         # noqa: E402
from secreview.llm.fallback import FallbackClient          # noqa: E402
from secreview.models import Finding                       # noqa: E402
from secreview.patch.engine import candidates              # noqa: E402
from secreview.redact import is_secret_file, llm_allowed, redact  # noqa: E402

# fake but correctly shaped values
OPENAI = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
GITHUB = "ghp_" + "a" * 36
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


def test_known_key_formats_are_masked():
    text = f'client = OpenAI(api_key="{OPENAI}")\nGH = "{GITHUB}"\naws = "{AWS}"\nauth = "{JWT}"'
    out = redact(text)
    for value in (OPENAI, GITHUB, AWS, JWT):
        assert value not in out
    assert "OpenAI(api_key=" in out and "<REDACTED:" in out


def test_credentials_in_uris_env_lines_and_literals_are_masked():
    text = ("MONGODB_URI=mongodb+srv://admin:Sup3rS3cret!@cluster0.example.net/db\n"
            "export STRIPE_SECRET_KEY=sk_test_51Habcdefghijklmnopqrstuv\n"
            'DB_PASSWORD = "hunter2-but-longer"\n'
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n")
    out = redact(text)
    for value in ("Sup3rS3cret!", "sk_test_51Habcdefghijklmnopqrstuv", "hunter2-but-longer", "MIIEowIBAAKCAQEA"):
        assert value not in out
    assert "mongodb+srv://admin:<REDACTED:password>@cluster0.example.net/db" in out


def test_ordinary_code_stays_readable():
    code = ('password = request.form["password"]\n'
            "PASSWORD_MIN_LENGTH = 8\n"
            'SECRET_KEY = os.environ.get("SECRET_KEY")\n'
            'token = "changeme"\n'
            'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n')
    assert redact(code) == code


def test_secret_findings_and_files_are_never_sent():
    def f(vclass, file):
        return Finding(rule_id="r", vuln_class=vclass, title="", file=file, line=1)
    assert not llm_allowed(f("hardcoded_secret", "app/settings.py"))
    assert not llm_allowed(f("client_side_secret", "src/config.js"))
    assert not llm_allowed(f("security_misconfig", ".env"))
    assert not llm_allowed(f("sqli", "deploy/prod.env"))
    assert llm_allowed(f("sqli", "app/routes.py"))
    for name in (".env", ".env.local", "server.pem", "secrets.toml", ".streamlit/secrets.toml", "id_rsa"):
        assert is_secret_file(name), name
    assert not is_secret_file("app/environment.py")


class Recorder(LLMClient):
    provider = "openrouter"
    is_cloud = True

    def __init__(self, replies=None):
        super().__init__(model="m", max_retries=0)
        self.prompts, self.replies = [], list(replies or [])

    def _complete(self, system, prompt, json_mode, temperature):
        self.prompts.append(prompt)
        return self.replies.pop(0) if self.replies else '{"verdict": "uncertain", "reason": "r"}'


def test_every_prompt_is_masked_before_it_is_sent():
    llm = Recorder()
    llm.complete("system", f'look at: key = "{OPENAI}"')
    assert OPENAI not in llm.prompts[0] and "<REDACTED:" in llm.prompts[0]


def test_secret_findings_never_reach_ground_or_patch(tmp_path):
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={OPENAI}\n")
    (tmp_path / "settings.py").write_text(f'API_KEY = "{OPENAI}"\n')
    llm = Recorder()

    class Gate:
        def client(self):
            return llm

    class Ctx:
        config, project = Config.load(), tmp_path
        def log(self, *a, **k): pass
        def warn(self, *a, **k): pass

    env_finding = Finding(rule_id="r", vuln_class="security_misconfig", title="", file=".env", line=1,
                          language="config")
    code_secret = Finding(rule_id="r", vuln_class="hardcoded_secret", title="", file="settings.py", line=1,
                          language="python")
    assert llm_ground(Ctx(), Gate(), env_finding) is False
    patches = candidates(Ctx(), Gate(), code_secret) + candidates(Ctx(), Gate(), env_finding)
    assert llm.prompts == []                      # nothing was sent to the LLM
    assert all(not p.llm_used for p in patches)   # deterministic fixes (e.g. move to os.environ) still apply


def test_stop_or_skip_interrupts_a_call_in_flight():
    """A hung request is abandoned within about half a second of Stop / Skip."""
    import threading
    import time as _time

    from secreview.context import StageSkipped

    release = threading.Event()

    class Hung(Recorder):
        def _complete(self, system, prompt, json_mode, temperature):
            release.wait(30)                       # a provider that does not answer
            return '{"late": true}'
    llm = Hung()
    pressed = _time.time() + 0.6

    def interrupt():
        if _time.time() > pressed:
            raise StageSkipped("verify")
    llm.interrupt = interrupt
    start = _time.time()
    with pytest.raises(StageSkipped):
        llm.complete("s", "p")
    assert _time.time() - start < 2.5
    release.set()


def test_empty_reply_benches_the_provider():
    openrouter, gemini = Recorder(["", '{"v": 1}']), Recorder(['{"v": 2}', '{"v": 3}'])
    gemini.provider = "gemini"
    chain = FallbackClient([openrouter, gemini], cooldown=300)
    assert chain.complete_json("s", "p1") == {"v": 2}
    assert chain.complete_json("s", "p2") == {"v": 3}     # openrouter skipped while cooling down
    assert len(openrouter.prompts) == 1
    with pytest.raises(LLMError, match="empty response"):
        Recorder([""]).complete("s", "p")
