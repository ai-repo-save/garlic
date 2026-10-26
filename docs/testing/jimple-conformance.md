# Jimple 有界差分语料

`tests/e2e/jimple_conformance.py` 是显式运行的集成测试。Soot、dexlib2 和 JVM 只作为测试依赖。

## 独立依据

- DEX 指令语义：https://source.android.com/docs/core/runtime/dalvik-bytecode
- DEX 指令格式：https://source.android.com/docs/core/runtime/instruction-formats
- DEX 数据布局、MUTF-8 和 payload：https://source.android.com/docs/core/runtime/dex-format
- Soot 4.6.0，提交 `38c9e53be2bb4ed6af90c332421d01de5734f388`：`src/main/grammar/jimple.scc`、`src/main/java/soot/jimple/ClassConstant.java`。
- smali，提交 `1a36aa30d18d92e63994f4b1e67a055931f5a707`：`smali-integration-tests/src/test/smali/junit-tests/InstructionTests/Format*`、`dexlib2/src/main/java/com/android/tools/smali/dexlib2/Opcode.java`、baksmali 的 `MultiSwitchTest` 和 `ZeroArrayPayloadWidthTest` 语料。

生成器使用 Soot 依赖包内的 dexlib2 正式 builder API。标准 opcode 和格式清单由该库的 DEX 039 表枚举，排除 ODEX 指令。测试不读取 Garlic 的 opcode 表。

Soot `ClassConstant.v()` 要求 slash 分隔的描述符，例如 `Ljava/lang/String;` 和 `[I`。对象及数组 Class 常量经 JVM 返回的实际 `Class` 对象验证。

## 执行顺序

1. 保存工具输入、Java 源文件的 SHA-256。复制候选 Garlic 到本次运行的 `tool/garlic`，保存源路径、SHA-256、Git HEAD 和 dirty 状态。
2. 用 `javac` 编译独立 Java oracle、DEX 生成器、Soot 消费者和 JVM 执行器。
3. dexlib2 生成每组独立的合法 DEX。Java oracle 先在 JVM 上产生期望结果。
4. 同一 DEX 经独立 Dexpler 转为 JVM class。消费者验证全部 concrete body、类标志、接口、方法和字段清单；ASM 独立读取实际产出的 class 清单。JVM 使用 `-Xverify:all` 执行，并与 Java oracle 精确比较。
5. 独立源验证通过后，通过固定 Garlic 的正式 MCP `jimple` 工具逐类取回 Jimple。Soot 严格验证、产出 class，JVM 执行相同输入，再与 Java oracle 精确比较。
6. 分别运行规范负例。保存全部组的失败并继续其他组。失败或超时返回退出码 1。

返回值比较保留整数类型、浮点原始位、UTF-16 代码单元、Class 名称以及数组的完整内容。字段组和 void invoke 组在调用后通过反射独立读取实际静态字段，验证已发生的写入。

原 DEX 的 Dexpler/JVM 结果与 Java oracle 不一致时，该组属于源验证或 oracle 能力问题，不作为 Garlic 红样。原始 stdout、stderr 和异常堆栈保留在运行目录。MCP 输出按 UTF-8 严格读取；非法 UTF-8 原始字节仍保留在 stdout 文件中。

## 分组与边界

| 组 | 有界样本 |
| --- | --- |
| IntLiterals / LongLiterals | const/4、16、32、high16、wide 各编码的有符号极值、非对称 64 位模式 |
| FloatLiterals / DoubleLiterals | 科学计数、正负 Infinity、canonical NaN、负零、最小次正规数 |
| FloatNanBits / DoubleNanBits | 非 canonical quiet NaN 的原始位模式 |
| StringAscii / StringUtf16 / StringNul | 空串、转义、jumbo 编码、中文、代理对、MUTF-8 NUL |
| Classes / PrimitiveClass | 对象、数组、基本类型 Class；基本类型独立分组以暴露 Dexpler/JVM 能力边界 |
| LiteralArithmetic | 全部 19 个 lit8/lit16 opcode，各取编码最小值和最大值，验证 Java int 溢出和移位掩码 |
| Packed / Sparse | 正常尾部、中部、零 case；case 和 default 实际执行 |
| Data / SharedArray | array-data 宽度 1、2、4、8；尾部、中部、零元素；两次 fill 共享同一 payload |
| Array / NestedArray | int、long、float、double、boolean、byte、char、short、引用元素的写入和读取，array-length，多维数组及数组 cast |
| Field | 上述元素类型的 instance/static 写入和读取，外部反射确认静态状态 |
| Call | static、virtual、direct、super、interface，各取 35c 和 range；long/double 参数占满五个寄存器槽，计算同时使用两个参数 |
| CallResults | 零参数 void、object 和 int 返回；move-result 家族；外部反射确认 void 调用写入 |
| Objects / Structure | monitor、check-cast、instance-of、implements、abstract、native 无体、clinit 的实际初始化效果 |
| Registers | move 家族、v15/v300、宽值和引用、高寄存器、goto 三种编码 |
| IntIf | if-eq、if-ne、if-lt、if-gt、if-le；同一组含零、负数、正数、相等和不等整数对，返回值是按对序的位图 |
| RefIf | 引用 if-eq、if-ne；同一引用、不同字符串、两个零寄存器、静态 null 字段与字符串、相同字符串常量、两个新对象、对象与自身 |
| High16 | const-wide/high16 的 0、Long.MIN_VALUE、-1<<48、1<<48、0x7fff<<48；与 LongLiterals 中的同指令分开，避免被其他 long 编码失败掩盖 |
| TypedArrayData | 中部 fill-array-data：boolean 0/1、char 0 与 U+FFEE、float -0 与 1.5、double -0 与 2.5 |
| CustomList / CustomRange | invoke-custom 与 invoke-custom/range。bootstrap 按 jadx `TestRawCustomInvoke` 调用 `Lookup.findStatic` 并返回 `ConstantCallSite`，目标是同组 `add(II)I` |
| PolymorphicList / PolymorphicRange | invoke-polymorphic 与 invoke-polymorphic/range。方法引用形状按 jadx `TestPolymorphicInvoke.smali`：`MethodHandle.invoke(Object[])Object` 加调用 proto `(Ljava/lang/String;)I` |

`const-string/jumbo` 验证 31c 编码，不宣称覆盖大于 65535 的真实字符串索引。寄存器样本不宣称覆盖 v65535。共享 switch payload 和 DEX 041 容器仍由库存明确显示缺口。

## 库存

`report.json` 的 `coverage` 按本次候选记录全部 224 个标准 opcode、格式及实际指令位置。状态如下：

- `executed-verified`：包含该 opcode 的显式调用方法通过三方比较；覆盖的是所列操作数和路径。
- `structure-only`：Garlic 输出通过 Soot 严格验证和 JVM class 清单验证，但没有包含该指令的显式调用方法通过语义比较。
- `missing-coverage`：缺少本次候选的有效证据。合法输入被拒绝、运行结果错误或源 oracle 不适用均保留原因。
- `explicitly-unsupported`：必须由产品契约明确授权。本测试不会把合法 opcode 的失败改成此状态。

样本存在与执行通过分别记录。helper 方法即使实际被间接调用，也只按结构验证计数，避免把静态可见指令误认为逐路径执行证明。格式通过表示该格式至少一个样本通过，不表示同格式全部 opcode 通过。

`coverage_union` 对新语料、既有算术语料和 control-flow 实际源 DEX 做去重并集。`external_evidence` 单独保存既有通过报告或日志、源 DEX 的 SHA-256 及生成器身份。既有算术 runner 使用临时 DEX，新工具通过其现有 `cases()` 和 `dex_fixture()` 重建同输入，只扫描，不声称本轮重新执行。control-flow 使用通过报告中 `build-fixture` 命令实际产出的 DEX，读取该运行的 `tool/identity.json`。算术日志与对应构建身份必须同时提供。外部候选与本轮候选分开记录；并集不等于最新候选的全部回归验证。

## 第三方能力边界

这些边界来自测试依赖的实际异常或写入拒绝，不作为 Garlic 绿样或红样。

- `const-class I`：DEX 允许基本类型描述符。原 DEX 的 Dexpler/JVM 抛出 `NoClassDefFoundError: I`，原因是 `ClassNotFoundException: I`。
- `const-method-handle`、`const-method-type`：Soot 4.6.0 自带的 `org.jf.dexlib2.writer.pool.ClassPool.internCode` 对指令引用类型 4（`METHOD_PROTO`）和 6（`METHOD_HANDLE`）抛出 `Unrecognized reference type`。同一 Soot 的 `InstructionFactory` 没有这两个 opcode，默认分支抛出 `IllegalArgumentException`。测试不手写 DEX 字节，也不把缺口改成通过。
- `invoke-polymorphic`、`invoke-polymorphic/range`：dexlib2 能写出合法指令，但只在同 DEX 已有相同 `method_id` proto 时才能解析 45cc/4rcc 的第二个引用。Dexpler 把它降成 `MethodHandle.invoke(Object[])`，写 class 时在 `BPrimitiveCastInst` 抛出 `invalid fromType java.lang.Object`。run08 源验证失败后不运行 Garlic。

`invoke-custom` 与 `invoke-custom/range` 已通过 Java oracle 和原 DEX 的 Dexpler/JVM 数值比较，不属于上述边界。

## 规范负例

- 将合法 `const/4` 的 opcode 改为规范保留值 `0x3e`，重新计算 DEX SHA-1 和 Adler-32；CLI 必须退出 2，MCP 必须报告相同失败，并记录实际 opcode 和指令位置。
- 将合法 int array-data 的 `element_width` 改为 3，重新计算校验字段；CLI 和 MCP 必须拒绝。该宽度不对应任何 DEX 原始元素类型。

合法的 filled-new-array、filled-new-array/range 和其他未实现指令属于正例。拒绝这些输入会使测试变红。

## 显式运行

构建和 Java 执行在 dev-builder 或任务指定服务器完成。先把候选及构建身份固定到项目内的独立运行目录。`--build-identity` 原样嵌入已有构建记录；记录应包含原路径、Git/dirty 状态、构建类型、编译器和依赖身份。

```sh
uv run tests/e2e/jimple_conformance.py \
  --garlic build/validation-tools/candidate/tool/garlic \
  --build-identity build/validation-tools/candidate/tool/identity.txt \
  --soot-jar build/validation-tools/soot-4.6.0-jar-with-dependencies.jar \
  --android-jar /home/dev/Android/Sdk/platforms/android-34/android.jar \
  --arithmetic-evidence-log build/validation-tools/arithmetic-pass.log \
  --arithmetic-build-identity build/validation-tools/arithmetic-candidate/tool/identity.json \
  --cfg-report build/validation-tools/control-flow/accepted-run/report.json \
  --work-dir build/validation-tools/conformance/unique-run
```

`--fixture-source-only` 仅验证独立输入。`--group` 可重复指定单组。编译器和消费者默认各有 180 秒预算；实际 fixture JVM 默认 10 秒预算，防止错误生成的自循环占用服务器。超时按失败记录，不重试。

每次运行创建独立 JSON 日志、命令 stdout/stderr、输入身份、原 DEX、Jimple、class 和机器可读报告。诊断产物不入 Git；验收与错误定位完成后按运行目录清理，重新执行同一命令可生成新产物。
