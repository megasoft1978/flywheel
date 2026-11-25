"""flywheel — Harbor custom agent for Terminal-Bench 2.0.

Runs the static Linux build of flywheel inside the task container,
talking to the host's OpenAI-compatible engine (Splash) via
host.docker.internal. Non-interactive one-shot mode per task.

usage:
  harbor run -d terminal-bench/terminal-bench-2 \
    --agent-import-path flywheel_agent:FlywheelAgent \
    -k engine_url=http://host.docker.internal:8021/v1 \
    --include-task-name <task>
"""

import shlex
from pathlib import Path

from harbor.agents.base import BaseAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

DIST = Path(__file__).resolve().parent.parent / "dist"


class FlywheelAgent(BaseAgent):
    def __init__(self, *args, **kwargs):
        self._engine_url = kwargs.pop("engine_url", "http://host.docker.internal:8021/v1")
        self._model = kwargs.pop("fw_model", None)
        self._turn_timeout = kwargs.pop("turn_timeout", 90)
        self._wall_timeout = kwargs.pop("wall_timeout", 1500)
        super().__init__(*args, **kwargs)

    @staticmethod
    def name() -> str:
        return "flywheel"

    def version(self) -> str | None:
        return "0.2"

    async def setup(self, environment: BaseEnvironment) -> None:
        """Pick the right arch binary and upload it into the container."""
        arch = "arm64"
        try:
            res = await environment.exec("uname -m", timeout_sec=15)
            out = (res.stdout or "").strip()
            if out in ("x86_64", "amd64"):
                arch = "amd64"
        except Exception:
            pass
        binary = DIST / f"flywheel-linux-{arch}"
        if not binary.exists():
            raise FileNotFoundError(
                f"{binary} missing — run bench-tb/build-linux.sh {arch} first"
            )
        await environment.upload_file(binary, "/usr/local/bin/flywheel")
        await environment.exec("chmod +x /usr/local/bin/flywheel", timeout_sec=15)

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        # write the instruction into the container (avoids quoting hell)
        instr = shlex.quote(instruction)
        await environment.exec(
            f"printf %s {instr} > /tmp/fw_instruction.txt",
            timeout_sec=15,
        )
        env = {
            "FW_ENDPOINT": self._engine_url,
            "HOME": "/root",
        }
        if self._model:
            env["FW_MODEL"] = self._model
        cmd = (
            "cd /app 2>/dev/null || cd /; "
            f"flywheel -f /tmp/fw_instruction.txt -T {self._turn_timeout} "
            f"-W {self._wall_timeout} --transcript /tmp/fw_transcript.jsonl "
            "> /tmp/fw_out.log 2>&1; echo FW_EXIT_$?"
        )
        res = await environment.exec(
            cmd,
            env=env,
            timeout_sec=self._wall_timeout + 120,
        )
        out = res.stdout or ""
        self.logger.info("flywheel exec tail: %s", out[-400:])
