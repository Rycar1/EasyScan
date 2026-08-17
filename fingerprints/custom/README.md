# HFinger 自定义指纹

把 `.yaml` 或 `.yml` 放入此目录，然后在 EasyScan 中打开：

**设置 → MITM 与实时分析 → HFinger 指纹识别 → 高级设置 → 重新加载规则**

也可以点击“添加 YAML 指纹”选择文件；桌面端会先使用 HFinger parser 与 schema 校验，再复制到此目录并热重载。

规则格式沿用 HackAllSec/hfinger。`example.yaml.disabled` 是最小示例，复制为 `example.yaml` 后即可启用。同名 `rule id` 会覆盖内置规则；某个文件解析失败时只跳过该文件，错误会显示在高级设置中。
