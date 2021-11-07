# 1m-block

usage
```
syntax : 1m-block <site list file>
sample : 1m-block top-1m.txt
```

# sqlite3
you need to install sqlite3
```
sudo apt-get install sqlite3 libsqlite3-dev
```

# iptable setting
```
sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE
sudo iptables -A INPUT -j NFQUEUE
```

# test and capture
![image](https://user-images.githubusercontent.com/45089989/140652040-415cf380-daf5-49cb-9ee9-34e3df1f7343.png)

I added test.gilgil.net to the list

![image](https://user-images.githubusercontent.com/45089989/140652066-1cf7f800-8f96-4b14-b33f-1e729ed1412a.png)
