# LLMalMorph3

LLMalMorph3 is a multi-agent automation framework for analyzing and transforming sample projects, coordinating build validation, sandbox submission, and reporting through a configurable pipeline.

## Cài đặt

1. Cài Python 3.11+.
2. Tạo virtual environment và cài dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Cách chạy

Lệnh chính hiện tại là `run_production_framework.py`.

```bash
python run_production_framework.py --config path\to\config.json
```

Chạy thử cấu hình mà không thực thi pipeline:

```bash
python run_production_framework.py --config path\to\config.json --dry-run
```

## Cấu trúc thư mục

- `agents/`: các agent điều phối luồng công việc.
- `adapters/`: adapter cho CAPE và VirusTotal.
- `broker/`: lớp giao tiếp message/broker.
- `contracts/`: dữ liệu và schema dùng chung.
- `llm/`: provider cho các backend LLM.
- `observability/`: logging, metrics, tracing.
- `src/`: logic lõi của pipeline và công cụ xử lý mã.
- `storage/`: lưu state, artifact, report.
- `tests/`: unit và integration tests.

## Biến môi trường cần có

File `.env` được nạp tự động khi chạy production framework. Các biến quan trọng:

- `CAPE_BASE_URL`
- `CAPE_API_TOKEN`
- `CAPE_BASIC_AUTH`
- `VIRUSTOTAL_API_KEY`
- `REDIS_URL`
- `FRAMEWORK_LOG_LEVEL`
- `FRAMEWORK_LLM_MODE`
- `FRAMEWORK_LLM_PROVIDER`
- `MISTRAL_API_KEY`
- `DEEPSEEK_API_KEY`
- `RUNPOD_API_KEY`
- `SALAD_API_KEY`
- `CLOUD_URL`
- `SALAD_URL`
- `OLLAMA_BASE_URL`
- `OLLAMA_API_KEY`
- `OLLAMA_TIMEOUT_S`
- `OLLAMA_NUM_CTX`
- `LLM_REQUEST_TIMEOUT_S`
- `AUTOFIX_LLM_TIMEOUT_S`
- `LLM_CLOUD_MODEL`
- `FIXER_MODEL`
- `ARTIFACT_ENCRYPTION_KEY`

## Ghi chú quan trọng

- Không commit `.env` thật hoặc bất kỳ key/token nào lên GitHub.
- Nếu dùng backend LLM từ xa, hãy kiểm tra `CLOUD_URL` hoặc `OLLAMA_BASE_URL` trước khi chạy.
- Dữ liệu đầu ra của pipeline được ghi vào `project_mutation_output/` và nên để ngoài version control.
- Với các sample lịch sử hoặc dữ liệu nhạy cảm, chỉ commit khi đã xác nhận rõ mục đích và giấy phép.