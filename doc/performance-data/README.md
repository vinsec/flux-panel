# 性能文章的数据依据

这里仅保留性能文章引用的数据。原始 JSON 沿用记录时的版本、字段和路径，不是安装步骤，也不代表当前公网跑分。

## GOST 与内核转发

[原始数据](gost-protocol-comparison.json) 包含 3／20 条规则、固定带宽 CPU、进程内存、持续 TCP／UDP 延迟、新连接和短传输结果，以及出口端口压力的补充诊断。

对应文章的主要对照为 3 条规则、同开 HTTP/TLS/SOCKS 屏蔽，三轮中位数。环境、被测文件校验和逐项区间均在 JSON 中。

[当时的完整性能报告](https://github.com/vinsec/flux-panel/blob/749666d51ae0be76cbf3970e870fe071f7b21663/doc/gost-protocol-comparison.md)

## 大规则查找结构优化

同一阶段的 1,000 条规则对照：

| 指标 | 逐条匹配方案 | 内核集合查找方案 |
|---|---:|---:|
| 短传输处理速率 | 0.265 Gbps | 14.373 Gbps |
| 固定 150 Mbps 时，整组 CPU 占一核比例 | 53.30% | 6.18% |
| 原始计数导出耗时 | 155.03 ms | 12.57 ms |

这是早期规则结构的同场对照，不是本项目与 Forwardx 的跑分。CPU 包含端点与控制程序，计数导出不包含完整上报和数据库处理。

[当时的完整测试方法与结果](https://github.com/vinsec/flux-panel/blob/749666d51ae0be76cbf3970e870fe071f7b21663/doc/forward-performance-v2.md)

## 统计与新连接优化

[原始数据](forward-performance-v55-validation.json) 保存相同协议屏蔽条件下的前后对照、轮次区间、CPU 采样和环境信息。文章引用的新连接速率为 9,006 → 9,502 次/秒；规则编码步骤为 17.3 → 2.5 ms。

[当时的完整性能报告](https://github.com/vinsec/flux-panel/blob/749666d51ae0be76cbf3970e870fe071f7b21663/doc/forward-performance-v55-validation.md)

## 统一管理后的性能验证

[原始记录](unified-agent-validation.json) 保留功能与性能验证结果。性能部分采用 3／10,000 条规则、150 Mbps 固定负载及串行新连接等测试；CPU 分配与前述实验不同，应使用各自的基线比较。

[当时的完整验证记录](https://github.com/vinsec/flux-panel/blob/749666d51ae0be76cbf3970e870fe071f7b21663/doc/unified-agent-validation.md)

返回 [性能文章](../transparent-forwarding-performance.md)。
