# DeepTrace File Inspector

A local Windows file inspector with a single malware finding and an optional technical breakdown. It does not execute submitted files or treat a static score as a malware verdict.

## Run it on Windows

Start the API in one terminal:

```powershell
cd backend
python -m pip install -r requirements.txt
python main.py
```

Start the frontend in a second terminal:

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173) on the same Windows computer. Keep both terminal windows open while using DeepTrace. The frontend proxies `/api` to the local service at `127.0.0.1:8000`.

## File checks

- Microsoft Defender on-demand scan of a temporary copy of the selected bytes. The scan uses Defender's custom file scan mode, checks that the path is not excluded and that the scan completed, then matches recent Defender Operational Event ID 1116 entries to the unique temporary path to obtain the engine's threat name and available severity/category details. See Microsoft's [custom scan instructions](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus) and [Defender event details](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus). A completed scan without a match is shown as “No threat detected,” not “safe.” If Defender cannot run, a path is excluded, or its event data cannot be read, the result is “Unable to verify.” Detection coverage depends on the installed security intelligence; keep Defender current. Defender may quarantine its temporary copy when it detects a threat; the app does not pass the selected original path to Defender.
- Optional MalwareBazaar hash lookup. Turn it on in the scanner to send only the SHA-256 hash—not the file—to MalwareBazaar. A known record can provide a family label and database first-seen time; it is external historical intelligence, not a new scan. No record is not evidence of safety. The API key is read only by the backend from `DEEPTRACE_MALWAREBAZAAR_API_KEY`; its [community API](https://bazaar.abuse.ch/api/) requires an Auth-Key.
- SHA-256, SHA-1, and MD5 hashes of the selected bytes.
- PE signature, selected PE headers, sections, debug timestamps, and a short list of process-access APIs from the import table. API imports indicate capability, not execution.
- Whole-file and per-section Shannon entropy, ASCII and UTF-16LE strings, and simple structural anomalies. Suspicious strings are kept ahead of ordinary strings when the result list is capped.
- A deterministic 0–100 triage score: malformed structure adds 45 points, whole-file entropy at or above 7.2 adds 25, and string patterns add up to 30. Separate 10-point clues cover high-entropy PE sections (when whole-file entropy is below 7.2), unusual section sizes, and two or more process-access API imports. The score is not a measured malware probability.
- PE compile/debug or PE/host timestamp ordering when debug data is absent. A mismatch is a review lead, not proof of timestomping; a reproducible-build marker suppresses wall-clock comparison because deterministic PE timestamps may be content-derived.
- Exact [EICAR antivirus test-pattern](https://www.eicar.org/download-anti-malware-testfile/) matching in the selected file and bounded ZIP contents. A match identifies the harmless test file; it is not a malware verdict.
- MalConv deep-learning inference for valid Windows PE files. It runs locally with the published EMBER research weights, reads the first 1 MiB, and reports a model output against a 0.50 review threshold. The breakdown also shows the three 500-byte windows most often selected by max pooling across the model's filters; these are model-internal activation locations, not causal explanations. The weights are historical and the output is not calibrated for current threats; it contributes only a secondary review clue and cannot name malware families. Bytes after the first 1 MiB are not scored.

The MalConv model is optional at runtime: install the listed backend dependencies and keep `backend/models/malconv_ember2018.h5` in place. Its upstream source, checksum, citation, and license are recorded in `backend/models/NOTICE.md`. The rest of the analysis still runs if the neural model cannot load. The primary result comes from Defender's own signature name when available; heuristic and neural indicators can ask for review, but they are not treated as confirmed malware detections.

To enable the optional hash lookup, set the API key in the same PowerShell window before starting the backend:

```powershell
$env:DEEPTRACE_MALWAREBAZAAR_API_KEY = "your-key"
python main.py
```

Leave the scanner's **Check MalwareBazaar by SHA-256** option off to keep all lookups local.

## Download trace

Use **Choose with Windows** to open the native file picker. For only the selected file, the local API reads its Windows `Zone.Identifier` stream and checks Chrome, Edge, and Brave download databases for a matching path, size, and SHA-256 when that hash is available. A matching record can provide the browser, recorded start/end time, URL chain, page URL, and referrer. The browser database is read locally and is not uploaded.

The browser's ordinary file picker cannot provide the original path, alternate data streams, or browser history. Its `lastModified` value is a file modification time, not download time. If no browser record is found, the trace reports that rather than guessing. Records may be missing after history cleanup, file renaming, or use of another browser. Windows file creation/modified times can change when copied and are shown separately.


