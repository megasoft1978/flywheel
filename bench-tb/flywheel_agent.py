"""flywheel — Harbor custom agent for Terminal-Bench 2.0.

Runs the static Linux build of flywheel inside the task container,
talking to the host's OpenAI-compatible engine (Splash) via
host.docker.internal. Non-interactive one-shot mode per task.

usage:
  harbor run -d terminal-bench/terminal-bench-2 \
    --agent-import-path flywheel_agent:FlywheelAgent \
    -k engine_url=http://host.docker.internal:8312/v1 \
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
        self._engine_url = kwargs.pop("engine_url", "http://host.docker.internal:8312/v1")
        self._model = kwargs.pop("fw_model", None)
        self._turn_timeout = kwargs.pop("turn_timeout", 150)
        self._wall_timeout = kwargs.pop("wall_timeout", 900)
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
            f"flywheel -q -f /tmp/fw_instruction.txt -T {self._turn_timeout} "
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
        # capture agent logs for postmortem into the trial's logging dir
        try:
            from harbor.models.trial.paths import TrialPaths  # noqa
        except Exception:
            TrialPaths = None
        import logging
        logdir = getattr(context, "logging_dir", None) or getattr(context, "trial_dir", None)
        for remote, name in (("/tmp/fw_out.log", "fw_out.log"),
                             ("/tmp/fw_transcript.jsonl", "fw_transcript.jsonl")):
            try:
                dl = getattr(environment, "download_file", None)
                if dl and logdir:
                    from pathlib import Path as P
                    dest = P(str(logdir)) / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    await dl(remote, dest)
                else:
                    r2 = await environment.exec(f"cat {remote} 2>/dev/null | tail -c 6000", timeout_sec=15)
                    if r2 and r2.stdout:
                        self.logger.info("%s tail:\n%s", name, r2.stdout[-3000:])
            except Exception as e:
                self.logger.info("log capture %s failed: %s", name, e)
