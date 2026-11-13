"""目标根内部布局（全部是普通本地文件）。

    target/
      objects/<key>                           可见对象（内容寻址）
      .replica/manifests/<sha256>.json        按内容摘要存放的清单
      .replica/published-root.json            当前 root 指针（原子替换）
      .replica/staging/<sha256>.json          分块传输日志
      .replica/staging/<sha256>.parts/        未完成的块（各自带摘要）
      .replica/staging/<sha256>.data          已整对象验证、待提升的暂存体
      .replica/quarantine/<slot>/...          目标已有损坏对象的留证副本
      .replica/evidence/                      对象级修复证据
      .replica/writer.lock                    写入互斥
"""

from __future__ import annotations

from pathlib import Path


def replica_root(target_root: Path) -> Path:
    return target_root / ".replica"


def manifest_store_path(target_root: Path, digest: str) -> Path:
    return replica_root(target_root) / "manifests" / f"{digest}.json"


def pointer_path(target_root: Path) -> Path:
    return replica_root(target_root) / "published-root.json"


def quarantine_root(target_root: Path) -> Path:
    return replica_root(target_root) / "quarantine"


def staging_root(target_root: Path) -> Path:
    return replica_root(target_root) / "staging"


def evidence_root(target_root: Path) -> Path:
    return replica_root(target_root) / "evidence"


def journal_path(target_root: Path, digest: str) -> Path:
    return staging_root(target_root) / f"{digest}.json"


def parts_dir(target_root: Path, digest: str) -> Path:
    return staging_root(target_root) / f"{digest}.parts"


def staged_data_path(target_root: Path, digest: str) -> Path:
    return staging_root(target_root) / f"{digest}.data"
