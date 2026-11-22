# Task 253 安全分析：multipart 边界解析与文件名编码

- 审计对象：本仓库 curl 源码快照（分支 `task/253`，HEAD `c3cbc16`）
- 审计方式：离线源码审查 + 本地已有测试用例复核，不依赖任何外部服务
- 审计日期：2026-11-22
- 范围：multipart 边界（发送侧生成 / 接收侧解析面）、Content-Disposition 引号参数、RFC 5987 `filename*`、异常分片（截断头部 / chunked 编码）、路径穿越、边界伪造、回调重入

---

## 0. 路径结论（最终核对，先行给出）

针对"服务器能否通过响应让 curl 把文件写到预期目录之外"这一问题，源码可直接证明的结论如下：

1. **服务器提供的文件名在使用前被归约为纯 basename。** `parse_filename()`（`src/tool_cb_hdr.c:150-227`）对 `Content-Disposition: filename=` 与 3xx `Location:` 两条来源，均执行：取最后一个 `/` 之后（`:186-188`）、再取最后一个 `\` 之后（`:193-195`）、截断首个 `\r`/`\n`（`:198-204`）、拒绝空串 / `"."` / `".."`（`:220-224`）。`../../etc/passwd`、`/etc/passwd`、`..\..\win.ini` 均被归约为 `passwd` / `win.ini`；纯 `..`、`.`、空名被拒绝并回退到 URL 派生名。
2. **`--output-dir` 拼接发生在归约之后。** `set_filename()`（`src/tool_cb_hdr.c:315-324`）执行 `"%s/%s", output_dir, filename`。由于步骤 1 的不变量（filename 不含 `/`、`\`，非空、非点），拼接结果必然位于 `output_dir` 之内。**路径穿越在 POSIX 与 Windows 上均被切断**（Windows 另有 `sanitize_file_name()` 处理盘符与保留名，`src/tool_cb_hdr.c:209-218`、`src/tool_doswin.c`）。
3. **不做任何百分号解码。** `filename=%2e%2e%2f` 按字面字符落盘（POSIX 上 `%` 是合法文件名字符），编码型穿越无效。文档明确声明此行为（`docs/cmdline-opts/remote-header-name.md`："There is no attempt to decode %-sequences"）。
4. **RFC 5987 / RFC 6266 `filename*=` 完全不解析**（`src/tool_cb_hdr.c:361-362` 注释 "encoded filenames (*=) are not supported"），且参数匹配 `memcmp(p, "filename=", 9)` 不会把 `filename*=` 误配为 `filename=`（第 8 字符 `*` ≠ `=`）。编码侧信道不存在。
5. **参数名大小写敏感、头部名大小写不敏感。** `FileName=` 不匹配（保守方向：忽略而非误用）；`CONTENT-DISPOSITION:` 能匹配（`checkprefix` 基于 `curl_strnequal`，`src/tool_cfgable.h:34`）。
6. **既有文件默认不被覆盖。** CD 文件名置 `is_cd_filename=TRUE`，`tool_create_output_file()` 走 `O_CREAT|O_EXCL`（`src/tool_cb_wrt.c:83-92`），服务器无法借 `-J` 静默覆写已有文件（除非显式 `--clobber`）。

---

## 1. 解析状态梳理：四个目标面

### 1.1 multipart 响应边界 —— 结论：接收侧不存在解析器

全库检索确认：**libcurl 不解析 multipart 响应体**。`boundary` 相关代码全部位于发送侧（`lib/mime.c` 编码器、`lib/formdata.c`、`lib/http.c:2186` 设置请求 Content-Type）；接收路径（`lib/http.c`、`lib/transfer.c`、`lib/http_chunks.c`、`lib/content_encoding.c`）中没有任何 boundary 匹配逻辑（唯一命中是 `lib/http.c:628` 注释中的 "auth boundary"，与 MIME 无关）。`multipart/byteranges`、`multipart/mixed` 响应体被当作不透明字节流交给写回调。

**安全含义**："multipart 响应边界伪造"在 curl 中没有攻击面——没有解析器就没有可伪造的对象。若上层应用自行解析 multipart 响应，该解析器的安全性不在本结论覆盖范围内。

### 1.2 发送侧 multipart 边界 —— 随机边界 + 显式状态机

- **生成**：`curl_mime_init()`（`lib/mime.c:1249-1270`）：24 个 `-` 前缀 + 22 个随机字母数字字符（`lib/mime.h:28-29,97`，`MIME_BOUNDARY_LEN = 46`）。随机源 `Curl_rand_alnum()` → `randit()`（`lib/rand.c:87`）→ 优先 `Curl_ssl_random()`（TLS 后端 CSPRNG）；拒绝采样消除模偏差（`lib/rand.c` 中 `while(r >= (UINT_MAX - UINT_MAX % alnumspace))`）。22 个 alnum 字符 ≈ 131 bit 熵，边界不可预测、不可伪造。
- **降级路径（需关注）**：无 TLS 的构建走 `weak_random()`（`lib/rand.c`）：Windows 用 `curlx_win32_random`，有 `arc4random` 用 `arc4random`，否则退化为时间种子 LCG 并打印 `WARNING: using weak random seed`。**在无 TLS 且无 arc4random 的构建上，边界熵不足，multipart 结构注入（正文内含边界串导致 part 伪造）风险从"可忽略"上升为"取决于攻击者能否预测时间种子"**。此类构建本身会收到运行时警告。
- **DEBUGBUILD 后门**：`CURL_ENTROPY` 环境变量可固定随机数（`lib/rand.c:91-110`），仅供测试（`tests/data/test1647`、`test1972` 等用它固定边界做字节级比对），非 DEBUGBUILD 不编译此分支。
- **状态机**：`mime_subparts_read()`（`lib/mime.c:920-970`）以 `MIMESTATE_BEGIN/BOUNDARY1/BOUNDARY2/CONTENT/END` 推进；`readback_bytes()`（`lib/mime.c:675-701`）用单调递增的 `state->offset` 支持任意大小的调用方缓冲区把边界串切片读出——**异常分片（边界横跨多次 read 回调）是设计内情形**，不变量为 `offset` 只增不减、段+尾（trail）读尽后返回 0。末尾 part 用 `--\r\n` 收尾、中间 part 用 `\r\n`（`lib/mime.c:940-944`），最终边界闭合无歧义。
- **正文不扫描边界**：curl 不检查/转义 part 正文里出现的边界串，完全依赖 131 bit 随机性避免碰撞。这是合理设计，但意味着"边界不可预测"是唯一的结构完整性保证——凸显上一段 weak_random 路径的重要性。

### 1.3 引号参数与 RFC 5987 文件名 —— 接收侧刻意最小化

`content_disposition()`（`src/tool_cb_hdr.c:336-416`）的参数扫描：

- 跳过非字母字符定位参数名（`:367`），`memcmp(p, "filename=", 9)` 精确匹配（`:372`），边界检查 `p > end - 9` 保证不越界读（`:369`）。
- 引号处理在 `parse_filename()`：值以 `'` 或 `"` 开头则以该字符为终止符（`:163-167`），`strchr` 找闭合引号（`:170-172`）。**不处理反斜杠转义**：`filename="a\"b"` 会在 `\"` 的 `"` 处截断——与 RFC 2616  quoted-string 语义不符，但方向保守（截短而非延长），且截断结果再经 basename 归约，不构成注入。
- 未闭合引号（uneven quotes）容忍：`strchr` 返回 NULL 则用到行尾，再截 `\r\n`。由 `tests/data/test1313` 复核（`filename='name1313` 无闭合引号 → 落盘 `name1313`）。
- `filename*=`：见 §0.4，完全不支持，属已知功能缺口而非漏洞（`docs/TODO.md:834` 记录）。

### 1.4 异常分片 —— 头部与 chunked 两条汇聚路径

- **头部行分片**：`http_parse_headers()`（`lib/http.c:4274+`）把不完整行累积进 `data->state.headerb` dynbuf（`lib/http.c:4332`），该 dynbuf 上限 `CURL_MAX_HTTP_HEADER`（100 KB，`lib/url.c:478`、`lib/easy.c:1023`）。**头部回调只会收到完整行**，不会收到半行；折叠行（obs-fold）在 `lib/http.c:4286-4301` 显式合并。单行超 100 KB → dynbuf 失败 → 传输中止。
- **头部合法性**：`http_rw_hd()` 前的校验（`lib/http.c:3680-3702`）拒绝 NUL 字节、行内孤立 CR、无冒号行（`CURLE_WEIRD_SERVER_REPLY`）。总量上限：单响应 300 KB / 全连接 6 MB（`Curl_bump_headersize`，`lib/http.c:3706-3731`），头字段计数上限 5000（`MAX_HTTP_RESP_HEADER_COUNT`，`lib/headers.c:370-374`）。
- **chunked 编码**：`lib/http_chunks.c` 显式状态机（`CHUNK_HEX/LF/DATA/POSTLF/TRAILER/...`），hex 长度串限长 `CHUNK_MAXNUM_LEN = 17`（`lib/http_chunks.h:40`），非 hex 字符报错（`lib/http_chunks.c:158`），数值经 `curlx_str_hex` 上限 `CURL_OFF_T_MAX`（`:167`），`CHUNK_FAILED` 为终态。畸形分片不会溢出长度解析。

---

## 2. 关键调用链

### 2.1 服务器文件名 → 落盘（-OJ）

```
lib/http.c http_parse_headers()          ; 累积完整行（≤100KB），校验 NUL/CR
  → Curl_client_write(CLIENTWRITE_HEADER)
    → src/tool_cb_hdr.c tool_header_cb()          (:423)
        ; 仅 2xx/3xx 且 honor_cd_filename 时进入 (:480,:497)
      → content_disposition()                     (:336)
          ; "Location:"(3xx) 临时名 (:343-358) / "Content-disposition:" (:359)
        → parse_filename()                        (:150)  basename 归约 + 拒绝 .././空
        → set_filename()                          (:304)  output_dir 拼接；流已开则拒绝
        → tool_create_output_file()  (tool_cb_wrt.c:74)  O_EXCL 防覆盖
        → tool_write_headers()                    (:229)  倾泻缓冲头部并置空链表
```

### 2.2 客户端 multipart 生成（-F / curl_mime）

```
curl_mime_init()        (lib/mime.c:1249)  24×'-' + 22 随机 alnum 边界
curl_mime_addpart()/…
Curl_mime_prepare_headers() (lib/mime.c:1800+)
  → add_content_disposition() (lib/mime.c:1742)  转义 name/filename
      → escape_string()       (lib/mime.c)  form 策略 %22/%0D/%0A；mail 策略反斜杠转义
        ; mail 策略遇 CR/LF 直接拒绝（CURLE_BAD_FUNCTION_ARGUMENT，:1767-1770）
mime_subparts_read()    (lib/mime.c:920)   BOUNDARY1→BOUNDARY2→CONTENT→END 状态机
  → readback_bytes()    (lib/mime.c:675)   offset 单调推进，支持任意切片
```

### 2.3 输入约束与状态不变量汇总

| 不变量 | 强制点 |
|---|---|
| 头部回调只收完整行，单行 ≤100 KB | `lib/http.c:4332` + `lib/url.c:478` |
| 头部不含 NUL / 孤立 CR | `lib/http.c:3680-3702` |
| 响应头总量 ≤300 KB、条数 ≤5000 | `lib/http.c:3706-3731`、`lib/headers.c:370` |
| 落盘文件名无 `/`、`\`，非空非 `.`/`..` | `src/tool_cb_hdr.c:186-224` |
| `output_dir` 拼接在归约之后 | `src/tool_cb_hdr.c:315-324` |
| CD 文件名不覆盖既有文件（默认） | `src/tool_cb_wrt.c:83-92`（`O_EXCL`） |
| CD 文件名只处理一次 | `honor_cd_filename=FALSE`（`src/tool_cb_hdr.c:393`） |
| 流已打开则拒绝改名 | `set_filename()` 首查 `outs->stream`（`:307-311`） |
| 边界熵 ≥ 22 alnum（CSPRNG） | `lib/mime.c:1258-1265`、`lib/rand.c` |
| 状态机 offset 单调、trail 读尽返回 0 | `lib/mime.c:675-701` |

---

## 3. 风险分析

### 3.1 路径穿越 —— 已切断（源码可证明）

攻击面是恶意服务器经 `Content-Disposition: filename=` 或 3xx `Location:` 控制落盘路径。§0 的六条结论逐条封闭：分隔符归约（`/`、`\`）、特殊名拒绝（`.`、`..`、空）、不解码 `%XX`、不解析 `filename*`、`output_dir` 后拼接、默认 `O_EXCL`。残余项仅在 Windows 特有面（盘符、保留设备名、尾部点/空格），由 `sanitize_file_name()`（`src/tool_doswin.c`）负责，本 POSIX 环境未执行验证（见 §5）。

### 3.2 边界伪造 —— 接收侧无攻击面；发送侧依赖 RNG 质量

- 接收：无 multipart 响应解析器（§1.1），伪造边界无处着力。
- 发送：正文不扫描边界串，结构完整性完全依赖边界不可预测。TLS 构建下 ≈131 bit 熵，伪造不可行；**无 TLS 且无 arc4random 的构建退化为时间种子 LCG**（`weak_random`，`lib/rand.c`），边界可预测，若应用把不可信内容嵌入 multipart part，理论上可构造 part 注入。该路径有运行时 `WARNING: using weak random seed` 提示。评级：默认构建（带 TLS）无风险；特殊裁剪构建需自行评估。

### 3.3 回调重入 —— 单向数据流，无可达重入

- `tool_header_cb()` 在 libcurl 内部被同步调用；回调内对 easy handle 只做 `curl_easy_getinfo()`（`:455,:478`，API 允许），无任何 `curl_easy_perform/PAUSE` 类重入调用。
- `content_disposition()` 在头部回调上下文里直接 `tool_create_output_file()` + `tool_write_headers()`——这是"回调里做 I/O"，但顺序受控：`honor_cd_filename` 先置 FALSE（`:393`）再开文件，同响应后续头部不会再进 CD 分支；`headlist` 释放即置 NULL（`:243-245`），无双重释放。
- `set_filename()` 在 `outs->stream` 已打开时返回 FALSE → `CURL_WRITEFUNC_ERROR` 中止传输（`:307-311`），杜绝"正文已开始写再换文件名"。
- 重定向序列：3xx `Location:` 设临时名（`alloc_filename=TRUE`），2xx CD 到来时 `set_filename()` 释放旧名再替换（`:312-313`），旧指针无留存，无 UAF。
- DEBUGBUILD 下写回调对 `OutStruct` 做一致性断言（`src/tool_cb_wrt.c:320-345`），状态机错位在调试构建中可被发现。

### 3.4 异常输入的拒绝方向

全部解析偏差都朝"保守拒绝/截断"方向：不闭合引号→截到行尾；转义引号→提前截断；大小写不符的参数名→忽略；非法头部（NUL/孤立 CR/无冒号）→ `CURLE_WEIRD_SERVER_REPLY`；超长行/超多条目→中止。未发现"解析差异导致放行更多内容"的宽松分支。

---

## 4. 可复核证据（本地源码 / 已有测试）

**证据 E1（路径穿越切断，测试级）**：`tests/data/test1585` —— 服务器返回 `Content-Disposition: filename=log\server\name%TESTNUMBER`，验证段断言落盘文件为 `%LOGDIR/name%TESTNUMBER`。即反斜杠路径被剥离、仅 basename 落盘，直接复核 `src/tool_cb_hdr.c:193-195`。

**证据 E2（引号参数容错，测试级）**：`tests/data/test1313` —— `Content-Disposition: inline; filename='name%TESTNUMBER`（引号不闭合），断言落盘 `%LOGDIR/name%TESTNUMBER`，复核 `parse_filename()` 对未闭合引号的截断路径（`src/tool_cb_hdr.c:170-172` + `:198-204`）。

**证据 E3（发送侧文件名转义，测试级）**：`tests/data/test1187` —— `-F 'filename="strange\file\"name"'` 经 mail 策略转义为 `filename="strange\\file\"name"` 出现在线上报文中，复核 `escape_string()` mimetable 分支（`lib/mime.c`）。`tests/data/test1158`/`test1186` 复核 form 策略的 `"` → `%22` 百分号编码（WHATWG 4.10.21.8 规则）。

**证据 E4（重定向文件名回退，测试级）**：`tests/data/test1642`（无 CD 时用 `Location:` 名）、`tests/data/test1487`（301 上的 CD），复核 `content_disposition()` 的 Location 分支（`src/tool_cb_hdr.c:343-358`）。

**证据 E5（边界随机性可固定 ⇒ 边界来自 RNG，测试级）**：`tests/data/test1647`、`test1972` 用 `CURL_ENTROPY`（仅 DEBUGBUILD，`lib/rand.c:91-110`）固定边界做字节比对，旁证生成路径 `curl_mime_init()` → `Curl_rand_alnum()`（`lib/mime.c:1258-1265`）。

**证据 E6（接收侧无 multipart 解析器，源码级）**：`grep -rn "boundary" lib/http.c lib/transfer.c lib/http_chunks.c lib/content_encoding.c` 无解析命中；全部 boundary 逻辑在 `lib/mime.c`（发送侧编码器）。

## 5. 源码可直接证明 vs 尚缺证据

**可直接证明（本报告结论均落在此类，除注明外）**：
- §0 全部路径结论（`parse_filename`/`set_filename`/`tool_create_output_file` 顺序与不变量）。
- 接收侧不存在 multipart 边界解析器。
- `filename*=` 不解析、`%XX` 不解码、参数名大小写敏感。
- 头部完整行交付、100 KB/300 KB/5000 条上限、NUL/CR 拒绝。
- 发送侧边界长度与随机源调用链；mail 策略对 CR/LF 的拒绝（`lib/mime.c:1767-1770`）。
- 回调路径无重入 libcurl 的调用；`honor_cd_filename` 一次性语义。

**尚缺证据（本报告不下结论或仅标注风险）**：
1. **HTTP/2、HTTP/3 路径**：头部经 nghttp2/ngtcp2 进入同一 `tool_header_cb`，其等价的 NUL/长度约束由各自 HPACK/QPACK 层保证，本次未逐行核对 h2/h3 头部校验代码。
2. **Windows `sanitize_file_name()` 实际行为**：源码在（`src/tool_doswin.c`），但本 POSIX 环境无法执行验证；盘符、保留名（CON、NUL、COM1…）、尾部点/空格的过滤以 Windows 平台测试为准。
3. **`weak_random()` 路径的实际可利用性**：源码证明其熵弱（时间种子 LCG），但"攻击者预测边界并完成 part 注入"的端到端可利用性未构造 PoC 验证。
4. **`filename` 与 `filename*` 并存时的 RFC 6266 优先级**：curl 取 `filename=` 忽略 `filename*=`，与 RFC 建议相反；属于互操作性偏差，本次未发现其构成安全问题的证据，但也未做对抗性构造验证。
5. **终端转义注入**：归约后的文件名可含 ESC 等控制字符（仅 `\r`/`\n` 被截断），经 `warnf` 等打印到终端时存在转义序列注入的轻微面；未评估各终端实际影响。

## 6. 不依赖外部服务的验证判据

以下判据全部可在本仓库本地复核（无需网络）：

1. **静态判据 V1（路径归约）**：`sed -n '150,227p' src/tool_cb_hdr.c` 中必须同时存在：`strrchr(p,'/')`、`strrchr(p,'\\')`、`\r`/`\n` 截断、`!"." && !".."` 拒绝，且 `set_filename()` 的 `output_dir` 拼接（`:315-324`）在调用链上位于 `parse_filename()` 之后。任一缺失即判失败。
2. **静态判据 V2（无 RFC5987 解码面）**：`grep -rn "filename\\*" src/ lib/` 无解析命中；`src/tool_cb_hdr.c:361` 附近保留 "encoded filenames (*=) are not supported" 注释。
3. **静态判据 V3（接收侧无边界解析器）**：`grep -rn "boundary" lib/http.c lib/transfer.c lib/http_chunks.c lib/content_encoding.c` 不得出现匹配逻辑（注释除外）。
4. **静态判据 V4（头部上限）**：`lib/url.c` / `lib/easy.c` 中 `headerb` 以 `CURL_MAX_HTTP_HEADER` 初始化；`lib/http.h` 定义 `MAX_HTTP_RESP_HEADER_SIZE`/`MAX_HTTP_RESP_HEADER_COUNT` 且在 `Curl_bump_headersize`、`Curl_headers_push` 中被强制执行。
5. **动态判据 V5（本地测试集）**：构建后运行 `make test TESTS="1311 1313 1487 1585 1642 1187 1158 1186"`（或 `runtests.pl 1311 1313 1487 1585 1642 1187 1158 1186`），全部通过即复核 E1–E4。
6. **动态判据 V6（边界熵来源）**：DEBUGBUILD 下 `CURL_ENTROPY=12345678` 运行任意 `-F` 上传用例（如 test1972），两次运行边界字节完全一致 ⇒ 证明边界确由 `Curl_rand_alnum` 产生且可被熵源控制；非 DEBUGBUILD 下该环境变量无效（`lib/rand.c` `#ifdef DEBUGBUILD`）。
7. **动态判据 V7（异常分片）**：本地构造（如 `tests/data` 自定义用例 + sws 测试服务器）返回跨多个 TCP 段切分的超长 `Content-Disposition` 行（<100 KB），断言 curl 落盘文件名正确；再构造 >100 KB 单行，断言传输以写错误中止而非截断落盘。

## 7. 残余风险与建议

| 项 | 级别 | 说明 |
|---|---|---|
| 无 TLS 构建的弱边界熵 | 中（条件性） | `weak_random()` LCG 路径可预测边界；建议此类构建避免用 multipart 承载不可信内容，或确保 `arc4random` 可用 |
| 文件名控制字符入终端 | 低 | 归约后文件名可含 ESC；建议显示前过滤控制字符 |
| `filename*` 不支持 | 低（功能） | 已知 TODO（`docs/TODO.md:834`）；安全方向为保守 |
| Windows 文件名过滤未本地验证 | 待验 | 建议在 Windows CI 复核 `sanitize_file_name` 对 `C:`、`CON`、`foo.` 的处理 |
| h2/h3 头部约束未逐行核对 | 待验 | 建议后续按 §5.1 补齐 |

**总体结论**：在默认（带 TLS）构建下，multipart 边界与文件名编码相关路径未发现可被服务器利用的路径穿越、边界伪造或回调重入漏洞；路径结论如 §0 所述，全部可由本地源码与既有测试复核。
