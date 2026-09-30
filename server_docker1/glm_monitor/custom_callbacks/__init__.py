"""Cloud Security对 LiteLLM 的定制修改集合。

本包是Cloud Security在 LiteLLM 网关(192.168.3.124)上挂载的定制代码,
部署在 /home/app/litellm_custom/ 下, 通过 PYTHONPATH 让 litellm 进程可 import。

config.yaml 注册方式 (litellm_settings.callbacks):
  引用模块中已实例化的对象(不是类), 末尾是小写实例名:
  callbacks: [custom_callbacks.inflight_logger.inflight_logger]

目前包含的定制:
  - inflight_logger.InflightLogger
      请求到达/结束时把「在途信息」(人名/模型/输入token) 推送到 GLM 监控采集器,
      让监控页能实时看到"谁正在跑 / 输入多大" (不用等请求结束)。
      详见 inflight_logger.py 文件头注释。
"""
