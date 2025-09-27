import paramiko

def run_ssh_command(host_ip, username, ssh_key_path, command):
    """Connect to a remote host via SSH and run a command."""
    try:
        key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host_ip, username=username, pkey=key)

        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        ssh.close()
        return output, error
    except Exception as e:
        return "", str(e)
