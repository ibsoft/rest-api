import paramiko

class RemoteSSH:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
    
    def send_command(self, command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(self.host, self.port, self.username, self.password)
            stdin, stdout, stderr = ssh.exec_command(command)
            return True
        except Exception as e:
            print(e)
            return False
        finally:
            ssh.close()
    