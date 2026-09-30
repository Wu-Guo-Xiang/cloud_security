"""敏感数据识别。

入口：detectors.dispatcher.detect_all(text) → list[Match]
内部分发到三个 detector：
  - credential_detector：致命凭证（api_key / private_key / prod_password / db_connection）
  - pattern_detector：身份/通讯类正则 + 公司词库
  - presidio_detector：Microsoft Presidio NER（Step 3 占位，后续接入）
"""
