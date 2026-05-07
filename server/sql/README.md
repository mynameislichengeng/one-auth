# SQL 文件管理规范

> ⚠️ **铁律：每个 update 文件只能放 ONE 条 SQL 语句。**
>
> MySQL 的 DDL 语句（CREATE TABLE / ALTER TABLE 等）会触发**隐式提交**，
> 导致事务回滚失效。一文件一语句，确保失败影响范围明确、追踪精确。

## 目录结构

```
server/sql/
├── README.md         # 本文档
├── schema.sql        # 当前完整表结构（开发者参考，**不自动执行**）
├── embed.go          # go:embed 把 update/ 嵌入二进制
└── update/           # 增量变更（按时间顺序累积，只增不改）
    └── {YYYYMM}/
        └── update-{YYYYMMDD}.{N}__{描述}.sql
```

## 文件命名

| 部分 | 含义 | 例 |
|---|---|---|
| `update-` | 固定前缀 | |
| `YYYYMMDD` | 日期 | `20260504` |
| `.N` | 当天第 N 个变更（1 起；可选 0 padding） | `.01`、`.27` |
| `__描述` | 双下划线 + 简短英文/拼音 | `__create_table_users` |

完整示例：`update/202605/update-20260504.01__create_table_tenants.sql`

正则（migration 跑器认这个）：`^update-(\d{8})\.(\d+)(?:__(.{1,50}))?\.sql$`

## schema.sql

**用途**：反映当前数据库完整表结构，是开发者了解所有表、字段的唯一参考。

**规则**：
- 每次新增表或修改字段 → 必须同步更新此文件
- 只放 `CREATE TABLE`，不放 `ALTER`、`INSERT`
- 本地新建 MySQL 想直接灌结构时可以 `mysql ... < schema.sql`
- **不被 go:embed**，不参与启动自动迁移

## update/ 目录

**用途**：按时间累积所有变更（DDL + DML）。oneauth-server 启动时由
`internal/migration` 扫描所有未在 `auto_sql_record` 表登记的文件，按版本号
顺序自动执行。

**规则**：
1. 文件名严格遵循 `update-YYYYMMDD.N__描述.sql`
2. 一文件一条 SQL 语句（INSERT / UPDATE 也一样，养成习惯）
3. 已提交的文件**永不修改、永不删除**（已经在生产跑过了）
4. 文件内容追加 SQL 注释（`-- xxx` 或 `/* xxx */`）说明这次变更的目的
5. 通过 `go:embed` 嵌入二进制——**新增文件后必须 go build / 重新打镜像**才生效

## 操作示例

### 新增一张表

1. 在 `update/{YYYYMM}/` 创建：
   ```sql
   -- update-20260601.1__create_table_orders.sql
   CREATE TABLE IF NOT EXISTS orders ( ... );
   ```
2. 同步追加到 `schema.sql`
3. 重 build 后部署 → 启动时自动执行

### 改字段

1. 创建：
   ```sql
   -- update-20260601.2__add_column_orders_remark.sql
   ALTER TABLE orders ADD COLUMN remark VARCHAR(500) NULL AFTER status;
   ```
2. 同步更新 `schema.sql` 里 orders 的字段定义
3. 重 build 后部署

### 加种子数据

1. 创建（一文件一 INSERT）：
   ```sql
   -- update-20260601.3__seed_perm_order_read.sql
   INSERT INTO permissions (...) SELECT ... WHERE NOT EXISTS (...);
   ```
2. `schema.sql` 不动（结构未变）
3. 重 build 后部署

## 跑器行为

- 启动时建 `auto_sql_record` 表（已存在则跳过）
- 用 MySQL `GET_LOCK('oneauth_auto_sql_migration', 10)` 防多实例并发
- 扫描 update/ 全部文件，按 `(date, sequence)` 升序排
- 已执行的版本在 `auto_sql_record.version_index` 里
- 大于已执行最大版本的文件 → 待执行；逐个 db.Exec → 写记录
- 任何一步失败 → 终止迁移、记 slog.Error，**不阻塞 server 启动**
- 失败的脚本可在 admin 介入修复后下次启动重试
