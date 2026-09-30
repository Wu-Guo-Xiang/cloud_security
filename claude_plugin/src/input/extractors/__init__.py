"""按 Hook event 抽取待扫描文本。

入口：extractors.dispatcher.extract(event) → ExtractResult
按 hook_event_name + tool_name 分发到具体 extractor。
"""
