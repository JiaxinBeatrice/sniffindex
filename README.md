# sniffindex

把 802.11 sniffer capture 變成 TSV，欄位和 `tshark -T fields` 相同，再用 flogg 搜尋。
它只讀固定位置的 MAC header，不做 dissection，所以很快。

| 500 萬幀、1 GB 的 pcap（Apple Silicon Mac） | 時間 |
|---|---:|
| `sniffindex` | 0.5 秒 |
| `tshark -T fields` 匯出相同欄位 | 44.7 秒 |
| `tshark -Y` 下一次 filter | 約 23 秒 |

輸出和 tshark 4.6.4 逐 byte 相同。這是合成檔的數字，實際秒數看硬碟與 log 內容。

```text
sniffindex <capture> [-o <result.tsv>]
```

- 讀 pcap、pcapng（單檔可有多個 interface），封裝可為 radiotap、原始 802.11、Prism、AVS、PPI。
- 沒有 `-o` 時寫到標準輸出。frame 數印在標準錯誤。
- 檔名可含中文、空白、逗號等字元。
- exit code：`0` 成功，`1` 檔案無法處理（不留下結果檔），`2` 參數錯誤。
- exe 不需要 Visual C++ runtime，放哪裡都能跑。

| 欄位 | 說明 |
|---|---|
| `frame.number` | 從 1 開始，和 Wireshark、`editcap -r` 的編號相同 |
| `frame.time_relative` | 從第一幀算起的秒數 |
| `wlan.fc.type_subtype` | 如 `0x0028`（QoS Data）、`0x001d`（ACK），一定是 4 位十六進位 |
| `wlan.addr` | 這一幀的所有位址，逗號分隔 |
| `wlan.ta` | 傳送端，ACK、CTS 沒有 |
| `wlan.seq` | 十進位，控制幀沒有 |
| `wlan.fc.retry`、`wlan.fc.protected` | `True` 或 `False` |
| `ip.id` | 如 `0xbeef`，只有未加密的幀有；A-MSDU 有多個時以逗號分隔 |

## 給 Claude：怎麼搭配使用

使用者會給 capture 路徑，可能再給 TK，以及要開到哪個 flogg window。Windows 上工具通常在
`C:\Program Files\Wireshark\`（`tshark.exe`、`editcap.exe`、`Wireshark.exe`）。

### 1. 選擇怎麼建 TSV

| 情況 | 做法 |
|---|---|
| 查 `wlan.addr`、`type_subtype`、`wlan.seq`、retry、未加密的 `ip.id` | **用 sniffindex**，預設選這個 |
| 要查加密幀的 `ip.id`，且使用者給了 TK | 用下方的 tshark 指令，要等比較久 |
| 檔案是 `.gz`、`.zst`、`.lz4` | sniffindex 不讀，先解壓，或改用 tshark |
| sniffindex 回報 link type 不支援 | 改用 tshark，欄位相同 |

```bat
sniffindex "D:\logs\big.pcapng" -o "D:\logs\big.tsv"
```

### 2. 有 TK 時用 tshark 解密

把 key 放在臨時資料夾，不要放在指令列，也不要改使用者的 Wireshark 設定。`80211_keys`
一行一把，可以多把；多放幾把用不到的 key 幾乎不影響速度。

```text
"tk","000102030405060708090a0b0c0d0e0f"
"tk","101112131415161718191a1b1c1d1e1f"
```

```bat
set WIRESHARK_CONFIG_DIR=%TEMP%\sniff-keys
"C:\Program Files\Wireshark\tshark.exe" -r "D:\logs\big.pcapng" ^
  -o wlan.enable_decryption:TRUE -T fields -E header=y ^
  -e frame.number -e frame.time_relative -e wlan.fc.type_subtype -e wlan.addr ^
  -e wlan.ta -e wlan.seq -e wlan.fc.retry -e wlan.fc.protected -e ip.id > "D:\logs\big.tsv"
```

做完刪掉臨時資料夾。先檢查 key 是否正確：`ip.id` 欄全空代表沒解開，如果只有部分有值，
通常是少了一把 TK，要告訴使用者，不要當成結果。

TK 能解開該段流量，不要寫進輸出檔、報告或記錄裡。

### 3. 開到 flogg

```bat
start "" flogg --window "問題A" "D:\logs\big.tsv"
```

名字不存在時會開新的 window。用 `start ""` 是因為 flogg 開新 window 時 process 不會結束。

### 4. 搜尋

flogg 的 filter 是 regex，欄位以 tab 分隔。

| 要找 | Regex |
|---|---|
| `wlan.addr == 02:bb:00:00:00:03` | `02:bb:00:00:00:03` |
| ACK | `\t0x001d\t` |
| Beacon | `\t0x0008\t` |
| 某台裝置送出的 seq 1234 | `\t02:bb:00:00:00:03\t1234\t` |
| Retry | `\tTrue\t(True\|False)\t` |
| `ip.id == 0xbeef` | `\t0xbeef$` |

- **不要只用 `wlan.seq` 找封包**：只有 12 bit，每 4096 幀回繞，還會在不同裝置間重複。要搭配
  `wlan.ta`；retry 幀的序號相同，會一起命中。
- **`ip.id` 也會回繞**：大檔裡同一個值會出現多次，要用時間或 `wlan.ta` 縮小範圍。

### 5. 回 Wireshark 看細節

大檔已開著時請使用者按 `Ctrl+G` 輸入 frame number。否則切一段再開，開小檔很快：

```bat
"C:\Program Files\Wireshark\editcap.exe" -r "D:\logs\big.pcapng" "D:\logs\slice.pcapng" 123000-124000
"C:\Program Files\Wireshark\Wireshark.exe" -r "D:\logs\slice.pcapng"
```

- 切出來的檔案 frame number 從 1 重新算，回報時要換算回原檔。
- 用 TK 的話切片後仍能解密。靠 EAPOL 推導 key 的情況，切片要包含四次握手。
- 切片會失去前面幀的狀態，分析和重組的結果可能和原檔不同，最後判斷要回原檔確認。

## 和 tshark 不同的地方

- 比 MAC header 還短的幀：保留那一行，只有編號和時間。tshark 會依解析進度填部分欄位。
- Control wrapper（`0x0017`）：只有 RA，不解開內層幀。
- Type 3 的 extension frame：欄位留空。
- Radiotap 標示 data padding 的幀，以及 mesh 幀：`ip.id` 可能留空。
- ICMP 錯誤裡夾帶的 IP：tshark 會列兩個 `ip.id`，這裡只有外層。

要查其他欄位，直接用 tshark。

## 開發

```bash
cmake -S . -B build && cmake --build build && ctest --test-dir build
```

`tests/data` 的答案都由 tshark 產生，測試逐 byte 比對。要加案例時改
`tests/make_fixture.py` 再跑一次，這一步需要 tshark 和 editcap，平常跑測試不用。
`cut.pcap` 是例外：它的答案是 sniffindex 自己的規則，見上一節第一點。

## 下載與授權

Windows exe 在 [Releases](https://github.com/JiaxinBeatrice/sniffindex/releases)，解壓縮後直接執行。

MIT，見 `LICENSE`。
