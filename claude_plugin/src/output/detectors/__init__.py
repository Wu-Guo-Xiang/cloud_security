"""让 output/detectors 成为混合 package —— 同时能找到 input/detectors/ 里的子模块。

背景:
  output_scanner.py 把 output/ 放在 sys.path[0],input/ 放在 sys.path[1]。
  Python 定位 `detectors` package 时会先命中 output/detectors(因为这里有
  __init__.py),后续 `from detectors.credential_detector import detect` 就会去
  output/detectors 找,找不到 credential_detector.py。

修法:
  把 input/detectors 追加到本 package 的 __path__,让 Python 在两个目录里查找
  子模块。这是标准 namespace-like package trick,不需要改 output_scanner.py
  或 input/detectors 里的任何东西。
"""
from pathlib import Path as _Path

_INPUT_DETECTORS = _Path(__file__).resolve().parent.parent.parent / "input" / "detectors"
if _INPUT_DETECTORS.is_dir() and str(_INPUT_DETECTORS) not in __path__:
    __path__.append(str(_INPUT_DETECTORS))
