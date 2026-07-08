import json
import sys
import uuid
from pathlib import Path

from app import (
    ROOT,
    SESSIONS,
    append_audit,
    find_relevant_policies,
    load_config,
    load_policies,
    persist_session,
    route_answer,
    start_background_job,
)
from ariba_adapter import execute_action
from ml_pipeline.eda import aggregate, analyze_dir


SERVER_NAME = "sam-copilot-mcp"
PROTOCOL_VERSION = "2024-11-05"


def mcp_text(payload):
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}]}


def write_message(message):
    body = json.dumps(message, ensure_ascii=False).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.decode("utf-8").strip()
        if not line:
            break
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    content_length = int(headers.get("content-length", "0"))
    body = sys.stdin.buffer.read(content_length)
    return json.loads(body.decode("utf-8"))


def tools_list():
    return {
        "tools": [
            {
                "name": "procurement_chat",
                "description": "Run the local procurement chatbot with policy grounding.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string"},
                        "message": {"type": "string"},
                        "context": {"type": "string"},
                        "session_id": {"type": "string"},
                        "response_style": {"type": "string", "enum": ["human", "action", "structured", "json"]},
                    },
                    "required": ["message"],
                },
            },
            {
                "name": "procurement_execute",
                "description": "Simulate or execute an Ariba procurement action.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string"},
                        "action": {"type": "string"},
                        "details": {"type": "object"},
                        "simulate": {"type": "boolean"},
                    },
                    "required": ["role", "action"],
                },
            },
            {
                "name": "procurement_eda",
                "description": "Run local EDA over procurement documents.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "input_dir": {"type": "string"},
                        "output": {"type": "string"},
                    },
                    "required": ["input_dir"],
                },
            },
            {
                "name": "procurement_train",
                "description": "Launch a local training job for the procurement models.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "model_type": {"type": "string"},
                        "params": {"type": "object"},
                    },
                },
            },
            {
                "name": "procurement_validate",
                "description": "Launch a local validation job for the procurement models.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "model_type": {"type": "string"},
                        "params": {"type": "object"},
                    },
                },
            },
        ]
    }


def call_tool(name, arguments):
    config = load_config()

    if name == "procurement_chat":
        session_id = arguments.get("session_id") or f"mcp-{uuid.uuid4()}"
        role = arguments.get("role", "buyer")
        message = arguments.get("message", "")
        context = arguments.get("context", "")
        response_style = str(arguments.get("response_style", "human")).lower()
        payload = {"role": role, "message": message, "context": context, "response_style": response_style}
        session = SESSIONS.setdefault(session_id, {"role": role, "history": []})
        session["history"].append({"from": role, "text": message})
        policies = load_policies(config)
        relevant_policies = find_relevant_policies(payload, policies)
        answer, knowledge_item = route_answer(payload, config, relevant_policies)
        session["history"].append({"from": "assistant", "text": answer})
        persist_session(session_id)
        append_audit({
            "event": "mcp_chat",
            "session": session_id,
            "role": role,
            "topic": knowledge_item.get("id") if knowledge_item else None,
        })
        return mcp_text({
            "session_id": session_id,
            "answer": answer,
            "relevant_policies": [name for name, _ in relevant_policies],
        })

    if name == "procurement_execute":
        result = execute_action(
            arguments.get("action"),
            arguments.get("details", {}),
            config,
        )
        append_audit({"event": "mcp_execute", "action": arguments.get("action")})
        return mcp_text(result)

    if name == "procurement_eda":
        input_dir = Path(arguments["input_dir"])
        docs = analyze_dir(input_dir)
        report = aggregate(docs)
        output = arguments.get("output")
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        append_audit({"event": "mcp_eda", "input_dir": str(input_dir), "docs": len(docs)})
        return mcp_text(report)

    if name == "procurement_train":
        model_type = arguments.get("model_type", "lm")
        params = arguments.get("params", {})
        job_id = f"mcp-{model_type}-{uuid.uuid4().hex[:8]}"
        if model_type == "sentence_transformer":
            cmd = [
                sys.executable,
                str(ROOT / "ml_pipeline" / "train_sentence_transformer.py"),
                "--train-file",
                params.get("train_file", "train_pairs.tsv"),
                "--output-dir",
                params.get("output_dir", "./st_model"),
                "--model",
                params.get("model_path", config.get("embedding_model_path", "./models/embedding_model")),
                "--epochs",
                str(params.get("epochs", 1)),
            ]
            if "validation_split" in params:
                cmd.extend(["--validation-split", str(params["validation_split"])])
            if "seed" in params:
                cmd.extend(["--seed", str(params["seed"])])
        else:
            if params.get("mode", "finetune") == "scratch":
                cmd = [
                    sys.executable,
                    str(ROOT / "ml_pipeline" / "train_lm_from_scratch.py"),
                    "--corpus",
                    params.get("train_file", "dataset.txt"),
                    "--output-dir",
                    params.get("output_dir", "./lm_scratch"),
                    "--epochs",
                    str(params.get("epochs", 1)),
                ]
            else:
                cmd = [
                    sys.executable,
                    str(ROOT / "ml_pipeline" / "train_lm.py"),
                    "--train-file",
                    params.get("train_file", "dataset.txt"),
                    "--base-model-path",
                    params.get("base_model_path", config.get("local_model_path", "./models/procurement_lm")),
                    "--output-dir",
                    params.get("output_dir", "./lm_local"),
                    "--epochs",
                    str(params.get("epochs", 1)),
                ]
            if "validation_split" in params:
                cmd.extend(["--validation-split", str(params["validation_split"])])
            if "seed" in params:
                cmd.extend(["--seed", str(params["seed"])])
        log_path = start_background_job(cmd, job_id)
        append_audit({"event": "mcp_train", "model": model_type, "job_id": job_id})
        return mcp_text({"job_id": job_id, "log": log_path})

    if name == "procurement_validate":
        model_type = arguments.get("model_type", "lm")
        params = arguments.get("params", {})
        job_id = f"validate-{model_type}-{uuid.uuid4().hex[:8]}"
        cmd = [
            sys.executable,
            str(ROOT / "ml_pipeline" / "validate_model.py"),
            "--model-type",
            model_type,
            "--model-path",
            params.get("model_path", config.get("local_model_path", "./models/procurement_lm")),
            "--data-file",
            params.get("data_file", "dataset.txt"),
            "--output",
            params.get("output", f"validation_{model_type}.json"),
        ]
        if model_type == "sentence_transformer":
            cmd[cmd.index("--model-path") + 1] = params.get(
                "model_path",
                config.get("embedding_model_path", "./models/embedding_model"),
            )
            if "threshold" in params:
                cmd.extend(["--threshold", str(params["threshold"])])
        log_path = start_background_job(cmd, job_id)
        append_audit({"event": "mcp_validate", "model": model_type})
        return mcp_text({"job_id": job_id, "log": log_path})

    raise ValueError(f"Unknown tool: {name}")


def main():
    while True:
        message = read_message()
        if message is None:
            break

        method = message.get("method")
        message_id = message.get("id")

        if method == "initialize":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            )
            continue

        if method == "tools/list":
            write_message({"jsonrpc": "2.0", "id": message_id, "result": tools_list()})
            continue

        if method == "tools/call":
            params = message.get("params", {})
            try:
                result = call_tool(params.get("name"), params.get("arguments", {}))
                write_message({"jsonrpc": "2.0", "id": message_id, "result": result})
            except Exception as exc:
                write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "error": {"code": -32603, "message": str(exc)},
                    }
                )
            continue

        write_message(
            {
                "jsonrpc": "2.0",
                "id": message_id,
                "error": {"code": -32601, "message": f"Unsupported method: {method}"},
            }
        )


if __name__ == "__main__":
    main()
