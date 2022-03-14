1. Генерация пакетов:

```bash
$ python tcp-ip/main.py -tfile "dreamshed.txt" -work-folder "data/" -mode 0 -payload 32000 -ip-source "192.168.0.1" -ip-destination "192.168.0.2" -port-source 8080 -port-destination 9000 -ttl 64
```

2. Восстановление файла из пакетов:

```bash
$ python tcp-ip/main.py -mode 1 -work-folder "/"
```
