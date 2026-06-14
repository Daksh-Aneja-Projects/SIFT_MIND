import paramiko
import time
import sys

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

print("Waiting for SIFT VM to boot and SSH to become available...")
for attempt in range(60):
    try:
        client.connect('127.0.0.1', port=2222, username='sansforensics', password='forensics', timeout=5)
        print("Connected!")
        break
    except Exception as e:
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(5)
else:
    print("\nFailed to connect after 5 minutes.")
    sys.exit(1)

try:
    print("Checking /mnt/case...")
    stdin, stdout, stderr = client.exec_command('ls -la /mnt/case')
    out = stdout.read().decode()
    err = stderr.read().decode()
    if "No such file or directory" in err:
        print("/mnt/case does not exist. Creating it.")
        client.exec_command('sudo mkdir -p /mnt/case && sudo chown sansforensics:sansforensics /mnt/case')
    else:
        print("Contents of /mnt/case:")
        print(out)
        
    print("\nChecking desktop for case data...")
    stdin, stdout, stderr = client.exec_command('ls -la ~/Desktop')
    print(stdout.read().decode())
    
    print("\nChecking common case data locations...")
    stdin, stdout, stderr = client.exec_command('ls -la /cases 2>/dev/null || ls -la /mnt/ewf 2>/dev/null')
    print(stdout.read().decode())
    
finally:
    client.close()
