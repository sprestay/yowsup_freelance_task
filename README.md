# yowsup_freelance_task
Task for yowsup registration. In this repo ragistration is working, but you won`t login in this data)

В библиотеки yowsup необходимо внести изменения: 
  yowsup/env/env_android.py
      
      import os
      _MD5_CLASSES = "O1/DTWx0YZdGaVPFt7tihA==" if not 'md5' in os.environ else os.environ['md5']
      _VERSION = "2.21.12" if not 'version' in os.environ else os.environ['version']#20
      
Отправка сообщений пока не работает
