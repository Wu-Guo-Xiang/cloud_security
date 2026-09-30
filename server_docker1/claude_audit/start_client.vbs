' claude_audit_client 开机自启入口(无窗口)
' 用法:
'   1) Win+R -> shell:startup   打开当前用户的 Startup 目录
'   2) 把本文件的快捷方式(或本文件本身)放到该目录
'   3) 下次登录时会自动无窗口后台跑;日志见 client.yml 里的 log_file
'
' 手动测试:  wscript D:\cloud_security\claude_audit\start_client.vbs
' 手动停止:  任务管理器结束 pythonw.exe

Set oShell = CreateObject("WScript.Shell")
sBase   = "D:\cloud_security\claude_audit\"
sConfig = sBase & "client.yml"

' pythonw.exe 无控制台窗口;-m 走包入口
' 0 = 隐藏窗口, False = 不等待返回
oShell.Run "pythonw.exe -m claude_audit_client --config """ & sConfig & """", 0, False
