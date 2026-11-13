# 内容寻址湖副本的清单差异与定向修复

本项目保存虚构算力设施的仓库源表、湖文件与Python读取工具。现有工具仅加载输入并显示记录数，不执行事实加工、目录提交、汇总或联接。所有设备、组织和金额均为合成。

## 字段与单位

source/target为两个本地模拟对象根，source/root.json是入口；manifest键和对象键只允许相对路径，内容摘要不因名字相同就可信。replication配置列出入口摘要。

material-index.json记录全部输入内容哈希；fixtures保存原始资料与配置，计算输出可放.workspace-output，原始资料不应被覆盖。

## 运行已有读取器

Python 3.11以上，标准库即可，不需安装第三方依赖。

    python -m src.replica_reader fixtures/source/root.json
    python -m compileall -q src tests
    python -m unittest discover -s tests -v

## 清单闭包复制与定向修复

`src.replication` 在源/目标两个本地对象根之间验证不可变清单闭包并修复副本。
不配置云账号、不需要外部凭据；输入全部是普通本地文件。

不变量：

- 清单按内容摘要钉住：入口摘要来自 `replication.json`，父清单摘要写在其子清单里。
  递归校验父链，检测清单环、重复祖先、越界/绝对路径、同键不同摘要。
- 对象按“字节哈希”寻址；文件名只是定位提示。源端缺失或不符即阻塞，
  绝不从目标坏对象反向覆盖源。
- 目标已有对象也要重算摘要；损坏副本先移入 `.replica/quarantine/` 留证，再修复。
- 分块复制时每块是独立文件，块日志记录该块摘要 + 来源对象摘要 + 累计摘要；
  续传逐块重算，并核对源对象身份（路径/大小/mtime/inode/device）与完整摘要，
  不按“已写字节偏移”盲续。
- 整对象验证（长度 + SHA256）通过后才原子提升为可见对象；root 指针
  `.replica/published-root.json` 只在目标闭包独立验证通过后原子替换。
- 同一内容被多个清单/键引用只传一次，再逐键提升。
- 旧读者固定自己的指针快照；新发布不回收旧清单或旧对象。
  清理只删本次复制的临时块与暂存文件。
- `plan` 完全不写入；`repair`/`resume` 默认拒绝对仓库内 `fixtures/target` 写入，
  演练请用副本或 `demo`。

命令（配置里的相对路径以配置所在目录为基准）：

    python -m src.replication plan    path/to/replication.json   # 只读差异计划
    python -m src.replication repair  path/to/replication.json   # 中断注入 + 隔离 + 修复
    python -m src.replication resume  path/to/replication.json   # 不带中断的续传/收尾
    python -m src.replication verify  path/to/replication.json   # 从目标重建闭包核验
    python -m src.replication reader  path/to/replication.json   # 检查固定 root 的清单可读
    python -m src.replication demo                                # 临时副本上的完整演练

`fault_injection_after_chunks: [1]` + `chunk_bytes: 2` 的含义：复制 3 字节 `abc`
时写满第 1 个块（2 字节）后抛出中断，保留块与日志；`resume` 再次运行会
从磁盘重验块 0、确认源对象未变，再补齐块 1 并整对象验证后提升。

证据：目标 `.replica/evidence/` 下有两份 JSON —— `replication.*` 含源/目标闭包
摘要、去重计数、传输与中断记录、指针摘要；`objects.*` 含每个对象的源状态、
修复前目标状态、隔离路径及块级传输记录。`plan` 的 stdout 只描述计划本身。

## 固定容器

    docker build -t replica-reconciliation:local .
    docker run --rm replica-reconciliation:local

容器镜像以完整digest固定，默认仅检查输入契约；实现新增分析功能所需依赖由开发者明确登记。
