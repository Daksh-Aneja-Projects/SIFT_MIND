import paramiko
import sys

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    print("Connecting to SIFT VM...")
    client.connect('127.0.0.1', port=2222, username='sansforensics', password='forensics', timeout=10)
    
    print("Executing real analysis pipeline (sift-smoke)...")
    cmd = '''
    cd /home/sansforensics/sift-mind/project
    export PATH="$HOME/.local/bin:$PATH"
    export PYTHONPATH="src"
    python3 -m sift_mind.run sift-smoke --mode sift --case-root /mnt/case/real_evidence --manifest /mnt/case/real_evidence/real_manifest.json > /home/sansforensics/sift_run.log 2>&1
    cat /home/sansforensics/sift_run.log
    '''
    stdin, stdout, stderr = client.exec_command(cmd)
    
    for line in iter(stdout.readline, ""):
        sys.stdout.buffer.write(line.encode('utf-8', 'replace'))
        sys.stdout.flush()
        
    err = stderr.read()
    if err:
        print("STDERR:")
        sys.stdout.buffer.write(err)

finally:
    client.close()
