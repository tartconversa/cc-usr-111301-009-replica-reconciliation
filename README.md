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

## 固定容器

    docker build -t replica-reconciliation:local .
    docker run --rm replica-reconciliation:local

容器镜像以完整digest固定，默认仅检查输入契约；实现新增分析功能所需依赖由开发者明确登记。
