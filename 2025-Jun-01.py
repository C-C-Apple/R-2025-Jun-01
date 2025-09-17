# =====================================================================
# 1) ZIP展開＋70段スキャン＋TamperSuspect＋日付混在＋集計
# =====================================================================
import os, re, zipfile, json, hashlib
from pathlib import Path
import pandas as pd
from datetime import datetime

# 出力ディレクトリ
outdir = Path("/mnt/data/KABUKI_INV_2025-06-01_outputs")
outdir.mkdir(exist_ok=True)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def extract_zip_to_dir(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_to)
    return list(Path(extract_to).rglob("*"))

def scan_file_for_tamper(file_path, width_list):
    """指定された文字幅ごとにTamperSuspectをスキャン"""
    with open(file_path, "rb") as f:
        data = f.read()
    text = data.decode("utf-8","ignore")
    results = []
    for width in width_list:
        windows = [text[i:i+width] for i in range(0, len(text), width)]
        for w in windows:
            if re.search(r"\\u[0-9a-fA-F]{4}", w):
                results.append({"width": width, "window": w[:80]})
    return results

def normalize_time(t):
    try:
        return datetime.fromisoformat(t).isoformat()
    except:
        return t

# 70段スキャンの幅リスト
widths = [
  222,555,888,2222,5555,8888,12222,15555,18888,
  22222,25555,28888,32222,35555,38888,42222,45555,
  48888,52222,55555,58888,62222,65555,68888,72222,
  75555,78888,82222,85555,88888,92222,95555,98888,
  102222,105555,108888,112222,115555,118888,122222,
  125555,128888,132222,135555,138888,142222,145555,
  148888,152222,155555,158888,162222,165555,168888,
  172222,175555,178888,182222,185555,188888,192222,
  195555,198888,202222,205555,208888,212222,215555,
  218888,222222
]

# =====================================================================
# 2) PDF作成ユーティリティ（レポート出力用）
# =====================================================================
def make_pdf(path, text):
    from reportlab.platypus import SimpleDocTemplate, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import A4
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4)
    story = [Paragraph(t, styles["Normal"]) for t in text.split("\n")]
    doc.build(story)

# =====================================================================
# 3) 軽量ファイル保存（DATE_MAP / MIXED_DATE_MAPなど）
# =====================================================================
if not date_map_df.empty:
    for col in date_map_df.select_dtypes(include=[object]).columns:
        date_map_df[col] = date_map_df[col].astype(str).str.encode("utf-8","replace").str.decode("utf-8","replace")
    date_map_df.to_csv(outdir/"DATE_MAP.csv", index=False, encoding="utf-8")

if not mixed_df.empty:
    for col in mixed_df.select_dtypes(include=[object]).columns:
        mixed_df[col] = mixed_df[col].astype(str).str.encode("utf-8","replace").str.decode("utf-8","replace")
    mixed_df.to_csv(outdir/"MIXED_DATE_MAP.csv", index=False, encoding="utf-8")

# =====================================================================
# 4) テンプレ3（被害記録マッピング）出力
# =====================================================================
import pandas as pd
import json
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

outdir3 = Path("/mnt/data/KABUKI_INV_2025-06-01_outputs_template3")
outdir3.mkdir(exist_ok=True)

records = [
    {
        "date_utc7": "2025-06-14 22:20–23:00",
        "time_score": 3,
        "location": "ホーチミン市7区 自宅",
        "device": "iP15P-Ghost",
        "event_type": "電磁波攻撃（連続2回）",
        "impact": "身体振動＋Wi-Fi切断。端末入力が不能化。",
        "log_ref": "thermalmonitord-2025-06-14-2220.ips, JetsamEvent同時刻帯",
        "ref_diff": "DIFF_events.csv(line 220), DIFF_keywords.csv(line 88)",
        "screenshot": "IMG_20250614_2225.png",
        "ledger_no": 6,
        "net_context": "SSID=HOME_NET, RAT=LTE, MCC=452, MNC=04",
        "severity": "High (3)",
        "confidence": 0.85,
        "custody_capture": "sha256(元データ …)",
        "custody_analysis": "sha256(解析後 …)",
        "notes": "Appleサポートとの直接関連ログはなし",
        "flame_flag": "VN-Telco (Yes)"
    },
    {
        "date_utc7": "2025-06-22 12:20–16:00",
        "time_score": 2,
        "location": "コンビニ → 移動中",
        "device": "iP15P-Ghost",
        "event_type": "電磁波攻撃＋AirTag的追跡",
        "impact": "断続的な身体刺激。Find My周辺ビーコン通知。",
        "log_ref": "WifiLQMMetrics-2025-06-22-1230.json, FindMy-BLE-2025-06-22-1245.log",
        "ref_diff": "DIFF_events.csv(line 310), DIFF_keywords.csv(line 122)",
        "screenshot": "IMG_20250622_1235.png",
        "ledger_no": 7,
        "net_context": "SSID=BK-Cafe, MCC=452, MNC=04, RAT=LTE",
        "severity": "Critical (4)",
        "confidence": 0.90,
        "custody_capture": "sha256(元データ …)",
        "custody_analysis": "sha256(解析後 …)",
        "notes": "Appleサポート問い合わせ（6月JSON）で accountsd/RTCR の痕跡が同時刻帯に存在",
        "flame_flag": "Apple (Yes)"
    },
    {
        "date_utc7": "2025-06-23 16:30–23:00",
        "time_score": 3,
        "location": "ホーチミン市7区 自宅",
        "device": "iP15P-Ghost",
        "event_type": "電磁波攻撃＋停電＋追跡ビーコン",
        "impact": "断続的振動、電源ドロップ、画面フリーズ",
        "log_ref": "log-power-2025-06-23-1635.session, SiriSearchFeedback-2025-06-23-1700.json",
        "ref_diff": "DIFF_events.csv(line 450), DIFF_keywords.csv(line 201)",
        "screenshot": "IMG_20250623_1705.png",
        "ledger_no": 8,
        "net_context": "SSID=HOME_NET, MCC=452, MNC=04, RAT=LTE",
        "severity": "Critical (4)",
        "confidence": 0.95,
        "custody_capture": "sha256(元データ …)",
        "custody_analysis": "sha256(解析後 …)",
        "notes": "Appleサポート通話（6月複数回）と同期。友人7/12通話感染のパターンと一致。",
        "flame_flag": "Apple + Microsoft Azure Intune (Yes)"
    }
]

# CSV / JSON / TXT / PDF出力
csv_path = outdir3/"VICTIM_EVENTS_2025-06-01.csv"
pd.DataFrame(records).to_csv(csv_path, index=False, encoding="utf-8")

json_path = outdir3/"VICTIM_EVENTS_2025-06-01.json"
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(records, f, ensure_ascii=False, indent=2)

txt_path = outdir3/"VICTIM_EVENTS_2025-06-01.txt"
with open(txt_path, "w", encoding="utf-8") as f:
    for r in records:
        for k,v in r.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")

pdf_path = outdir3/"VICTIM_EVENTS_2025-06-01.pdf"
styles = getSampleStyleSheet()
doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
story = []
for r in records:
    for k,v in r.items():
        story.append(Paragraph(f"<b>{k}</b>: {v}", styles["Normal"]))
    story.append(Paragraph("----", styles["Normal"]))
doc.build(story)

# =====================================================================
# 5) テンプレ4（総括報告）出力
# =====================================================================
outdir4 = Path("/mnt/data/KABUKI_INV_2025-06-01_outputs_template4")
outdir4.mkdir(exist_ok=True)

summary = {
    "period": "2025-06-01",
    "devices": "iPhone 11 Pro / iPhone 12 mini-1 / iPhone 12 mini-2 / iPad / iP15P-Ghost / iPhone 12 Ghost",
    "log_count": "合計 5本（生ログ2本 + ZIP part1/2/3）",
    "summary_type": "1日分析（Phase 区間：S2 → S3 への橋渡し）",
    "custody": {
        "files": "filenames.txt / sizes.txt / sha256sum.txt",
        "master_sha256": "sha256_chain_generated.txt",
        "json_concat": "EVENTS_FULL.json + CLEAN.json",
        "csv_concat": "EVENTS_FULL.csv + CLEAN.csv",
        "media": "SanDisk Extreme PRO A2 microSD ＋ MEGA"
    },
    "csv_digest": {
        "IDMAP.csv": "PID/SessionID の有無をマーク済み",
        "EVENTS": "JP-Tamper抽出, VN時間統一",
        "PIVOT.csv": "RTCR / SiriSearchFeedback / triald 共起",
        "GAPS.csv": "RTCR=not_found, MetaAuth=found",
        "tamper_join_sec.csv": "bug225+777+309, time_score=3",
        "DIFF": "前回解析との差分追記済み"
    },
    "victim_sample": {
        "date_utc7": "2025-06-14 22:20",
        "time_score": 3,
        "location": "Ho Chi Minh 7区 自宅",
        "device": "iP15P-Ghost",
        "event_type": "電磁波攻撃（連続2回）",
        "impact": "身体振動＋Wi-Fi切断",
        "log_ref": "thermalmonitord-2025-06-14-2220.ips",
        "ref_diff": "DIFF_events.csv(line220)",
        "screenshot": "IMG_20250614_2225.png",
        "ledger_no": 6,
        "net_context": "HOME_NET LTE",
        "severity": "High(3)",
        "confidence": 0.85,
        "notes": "Appleサポートとの直接関連なし",
        "flame_flag": "VN-Telco(Yes)"
    },
    "options": {
        "bugtype_full": True,
        "usageClientId_norm": True,
        "assetd_freq": True
    },
    "usage": "Phase別総括, 国際報告, 裁判・交渉・学術文書化"
}

df = pd.json_normalize(summary)
csv_path = outdir4/"SUMMARY_TEMPLATE4.csv"
df.to_csv(csv_path, index=False, encoding="utf-8")

json_path = outdir4/"SUMMARY_TEMPLATE4.json"
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

txt_path = outdir4/"SUMMARY_TEMPLATE4.txt"
with open(txt_path, "w", encoding="utf-8") as f:
    for k,v in summary.items():
        f.write(f"{k}: {v}\n")

pdf_path = outdir4/"SUMMARY_TEMPLATE4.pdf"
styles = getSampleStyleSheet()
doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
story = []
def write_section(title, content):
    story.append(Paragraph(f"<b>{title}</b>", styles["Heading3"]))
    if isinstance(content, dict):
        for kk,vv in content.items():
            story.append(Paragraph(f"{kk}: {vv}", styles["Normal"]))
    else:
        story.append(Paragraph(str(content), styles["Normal"]))

for k,v in summary.items():
    write_section(k, v)
    story.append(Paragraph("----", styles["Normal"]))

doc.build(story)
