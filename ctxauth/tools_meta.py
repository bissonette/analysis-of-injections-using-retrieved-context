"""Общие сведения об инструментах (без зависимостей от RAG-модулей)."""
EXTERNAL_TOOLS = frozenset({"send_email", "http_get", "export_db"})
DESTRUCTIVE_TOOLS = frozenset({"delete_record"})
