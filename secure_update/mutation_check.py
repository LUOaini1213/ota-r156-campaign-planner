"""python -m secure_update.mutation_check：变异检查（开发工具，不在测试套件里）。

逐个“关掉”一道防线（只在子进程内存里打补丁，不改任何文件），再跑对应的测试，确认测试会失败。
如果某道防线关掉了测试还通过，说明测试没有真正覆盖它。在 P3 根目录运行，约 10 秒。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

P3 = Path(__file__).resolve().parents[1]
T = "secure_update/tests/"

MUTANTS = [
    ("不检查过期", "import secure_update.verifier as m; m.is_expired = lambda *a: False",
     [T + "test_su_metadata_attacks.py", "-k", "freeze or expired"]),
    ("不检查已信任元数据是否过期", "import secure_update.verifier as m; m.RepoVerifier.require_fresh = lambda self, now: None",
     [T + "test_su_metadata_attacks.py", "-k", "expired"]),
    ("不检查签名门限", "import secure_update.verifier as m; m.require_threshold = lambda *a, **k: None",
     [T + "test_su_image_key_attacks.py", "-k", "threshold or signature or revokes or root_rotation"]),
    ("root 轮换不查旧 root 门限",
     "import secure_update.verifier as m\norig = m.require_threshold\n"
     "def lax(env, role, root, **k):\n    return None if '旧 root' in k.get('label', '') else orig(env, role, root, **k)\n"
     "m.require_threshold = lax",
     [T + "test_su_image_key_attacks.py", "-k", "root_rotation_requires"]),
    ("不做 Director / Image 交叉核对",
     "import secure_update.verifier as m\norig = m.match_director_and_image\n"
     "def lax(name, d, i):\n    return orig(name, d, d if i is None else {**i, 'length': d['length'], 'hashes': d['hashes']})\n"
     "m.match_director_and_image = lax",
     [T, "-k", "mismatch_rejected or unlisted"]),
    ("镜像不设长度上限",
     "import secure_update.client as m\n"
     "def chunks(stream, remaining, size, what):\n    data = b''.join(stream)\n"
     "    for i in range(0, len(data), size):\n        yield data[i:i + size]\n"
     "m.bounded_chunks = chunks",
     [T + "test_su_image_key_attacks.py", "-k", "endless"]),
    ("不做下载前的镜像检查", "import secure_update.client as m; m.UpdateClient._precheck = lambda self, t: None",
     [T, "-k", "wrong_ecu or secure_version or release_counter or oversized"]),
    ("启动控制块非原子（总写第 0 份）",
     "import secure_update.nvstore as m\n"
     "def write(self, value, label):\n    seq = max((r['seq'] for r in self._copies().values()), default=0)\n"
     "    self.nv.write(f'{self.key}.0', m._pack({'seq': seq + 1, 'value': value}), label)\n"
     "m.RedundantRecord.write = write",
     [T + "test_su_ecu_client.py", "-k", "power_loss"]),
    ("bootloader 不复核哈希",
     "import secure_update.ecu as m\n"
     "def ok(self, slot, counter):\n    h = self.headers[slot].read()\n"
     "    return isinstance(h, dict) and bool(h.get('valid')) and h['secure_version'] >= counter\n"
     "m.ECU.slot_bootable = ok",
     [T + "test_su_ecu_client.py", "-k", "bootloader or power_loss"]),
    ("安装时就提升防回滚计数器",
     "import secure_update.client as m\norig = m.UpdateClient._verify_image\n"
     "def early(self, journal):\n    orig(self, journal)\n"
     "    self.ecu.raise_counter(journal['target']['secure_version'], 'early')\n"
     "m.UpdateClient._verify_image = early",
     [T + "test_su_ecu_client.py", "-k", "health_check or crashing or counter or power_loss"]),
]


def main() -> int:
    survivors = []
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    for name, patch, selection in MUTANTS:
        code = f"{patch}\nimport pytest, sys\nsys.exit(pytest.main(['-q', '-p', 'no:cacheprovider', *{selection!r}]))"
        proc = subprocess.run([sys.executable, "-B", "-c", code], cwd=P3, env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=300)
        lines = [line for line in proc.stdout.splitlines() if "passed" in line or "failed" in line]
        killed = proc.returncode != 0
        print(f"{'被测试发现' if killed else '没被发现！'} | {name} | {lines[-1] if lines else proc.stdout[-200:]}")
        if not killed:
            survivors.append(name)
    print("全部防线都有测试覆盖" if not survivors else f"没有被测试覆盖的防线：{survivors}")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
