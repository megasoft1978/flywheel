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

import re
import shlex
from pathlib import Path

from harbor.agents.base import BaseAgent
from harbor.agents.installed.base import (
    ApiError,
    ContextWindowExceededError,
    NonZeroAgentExitCodeError,
)
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

DIST = Path(__file__).resolve().parent.parent / "dist"
# context-size wording; also inside HTTP 500 and 200-body errors (harvest_tb21 uses the same)
CONTEXT_OVERFLOW = re.compile(
    r"context.{0,24}(length|window|size|limit)|maximum context|prompt is too long|exceeds? the context",
    re.IGNORECASE,
)


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
                f"{binary} missing — run bench-tb/build-zig.sh first"
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
            # the task container is throwaway and tasks write outside /app
            f"flywheel -q --allow-outside-writes "
            f"-f /tmp/fw_instruction.txt -T {self._turn_timeout} "
            f"-W {self._wall_timeout} -t 180 --transcript /tmp/fw_transcript.jsonl "
            "> /tmp/fw_out.log 2>&1; echo FW_EXIT_$?"
        )
        res = await environment.exec(
            cmd,
            env=env,
            timeout_sec=self._wall_timeout + 120,
        )
        out = res.stdout or ""
        self.logger.info("flywheel exec tail: %s", out[-400:])
        # keep the full log and transcript next to the trial for postmortems
        for name in ("fw_out.log", "fw_transcript.jsonl"):
            try:
                await environment.download_file(f"/tmp/{name}", self.logs_dir / name)
            except Exception as e:
                self.logger.warning("log capture %s failed: %s", name, e)
        await self._raise_on_failure(environment, out)

    async def _raise_on_failure(self, environment: BaseEnvironment, out: str) -> None:
        """Turn flywheel's exit status into the exception Harbor records.

        src/main.c exits 0 on finish=done and 1 on every other finish, so a normal task end
        (turns, wall, aborted) and a failed model request (error:...) differ only in the
        summary line.
        """
        m = re.search(r"FW_EXIT_(\d+)", out)
        code = int(m.group(1)) if m else None
        if code == 0:
            return
        res = await environment.exec(
            "grep -o 'flywheel: finish=.*' /tmp/fw_out.log | tail -n 1", timeout_sec=15
        )
        line = (res.stdout or "").strip()
        # no " turns=": a multi-line server error cut the summary line short
        m = re.match(r"flywheel: finish=(.*?)(?: turns=\d+|$)", line)
        finish = m.group(1) if m else None
        if code == 1 and finish is not None:
            if not finish.startswith("error:"):
                return
            if finish.startswith("error:status 4") and "context" in finish.lower():
                raise ContextWindowExceededError(f"flywheel {finish}")
            if CONTEXT_OVERFLOW.search(finish):
                raise ContextWindowExceededError(f"flywheel {finish}")
            raise ApiError(f"flywheel engine failure: {finish}")
        raise NonZeroAgentExitCodeError(f"flywheel exit status {code}: {line or 'no summary line'}")
