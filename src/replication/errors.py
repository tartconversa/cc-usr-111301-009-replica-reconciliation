"""复制器错误类型。

所有“数据不可信”的情况都走 Blocked，并且携带结构化证据；调用方据此决定是
继续修复其他对象还是整体退出。计划阶段使用 PlanRejected，保证只读模式绝不
会因为发现问题而写入任何东西。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ReplicaError(Exception):
    """复制器根异常。"""


class ConfigError(ReplicaError):
    """复制配置或输入契约不成立。"""


@dataclass
class Blocked(ReplicaError):
    """某一步被阻塞，附带机器可读的原因码与证据。

    code 是稳定字符串（测试与证据文件依赖它），detail 给出定位信息。
    阻塞永远不触发“从目标反向覆盖源”，也不把目标对象当成可信来源。
    """

    code: str
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.code, self.detail)

    def __str__(self) -> str:  # pragma: no cover - 便于日志阅读
        return f"{self.code}: {self.detail}"


class PlanRejected(ReplicaError):
    """只读计划阶段拒绝（例如清单环、越界键、同键异摘要、源损坏）。

    rejected 是 Blocked.code 的有序列表，方便一次性报告全部问题。
    """

    def __init__(self, rejected: list[Blocked]):
        self.rejected = rejected
        super().__init__("; ".join(str(b) for b in rejected))


class TransferInterrupted(ReplicaError):
    """注入的中断（模拟进程在块复制途中被杀）。

    committed_bytes/next_chunk 记录中断点，供恢复时与块日志独立核对。
    """

    def __init__(self, key: str, committed_bytes: int, next_chunk: int):
        self.key = key
        self.committed_bytes = committed_bytes
        self.next_chunk = next_chunk
        super().__init__(
            f"transfer interrupted: {key} after {committed_bytes} bytes "
            f"(next chunk {next_chunk})"
        )
