import os 

os.system('git clone https://github.com/gushmazuko/metasploit_in_termux.git')
os.chdir("metasploit_in_termux")
os.system('chmod +x  metasploit.sh')
os.system('bash ./install.sh')
