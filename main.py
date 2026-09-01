import html
import json
import os
import subprocess
import time
import urllib.parse
from itertools import count

import requests

print("Добро пожаловать в программу для проверки url-конфигов через Sing-box\nПеред запуском не забудьте выключить впн!\nНа данный момент поддерживаются только vless и hysteria2.\nПри возникновении ошибок пишите разработчику!")
link = input("Введите ссылку на список конфигов, где каждый конфиг с новой строки:\n")
#link = ""
list = requests.get(link).text.split("\n")
if len(list) < 2:
    if link.split("://")[0] != "hy2" and link.split("://")[0] != "hysteria2" and link.split("://")[0] != "vless":
        print("Список неверного формата")
        exit()
print("Рабочие конфиги будут записаны в файл valid.txt")
config = {}
params = []
name = ""
count = 0
skip = 0 # если нужно скипнуть первые конфиги
path_to_xray = "sing-box-1.14.0-alpha.23-windows-amd64/sing-box.exe"
config_path = "config.json"
real_ip = requests.get('https://api.ipify.org').text
proxies = {
    'http': 'socks5h://127.0.0.1:20000',
    'https': 'socks5h://127.0.0.1:20000'
}

def clean_config_url(raw_url):
    step1 = html.unescape(raw_url)
    step2 = urllib.parse.unquote(step1)
    return step2.strip()

for link in list:
    count += 1
    if count <= skip:
        continue
    link = clean_config_url(link)
    #print(link)
    """
    proto = link.split("://")[0]
    uuid = link.split("://")[1].split("@")[0]
    ip = link.split("@")[1].split(":")[0]
    if link.split("@")[1].split(":")[1].find("/") >= 0:
        port = int(link.split("@")[1].split(":")[1].split("/")[0])
    else:
        port = int(link.split("@")[1].split(":")[1].split("?")[0])
    if link.find("?") >= 0:
        if link.find("#") >= 0:
            params = link.split("?")[1].split("#")[0].split("&")
        else:
            params = link.split("?")[1].split("&")
    if link.find("#") >= 0:
        name = link.split("#")[1]
    """
    parsed = urllib.parse.urlparse(link)
    proto = link.split("://")[0]
    uuid = parsed.username
    ip = parsed.hostname
    port = parsed.port
    name = parsed.fragment
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

    opt = {}
    """
    for param in params:
        if param.split("=")[0] == "insecure":
            opt[param.split("=")[0]] = param.split("=")[1] == "1"
        else:
            opt[param.split("=")[0]] = param.split("=")[1]
    """
    for k in params:
        if k == "insecure" or k == "allowInsecure":
            opt[k] = params[k] == "1"
        else:
            opt[k] = params[k]
    if "sni" not in opt:
        opt["sni"] = ip
    if "insecure" not in opt:
        opt["insecure"] = False
    if "allowInsecure" in opt:
        opt["insecure"] = opt["allowInsecure"]
    if "encryption" not in opt:
        opt["encryption"] = "none"
    if "security" not in opt:
        opt["security"] = "none"
    if "flow" not in opt:
        opt["flow"] = "none"
    if "type" not in opt:
        opt["type"] = "none"
    if proto == "vless":
        config: dict = {
            "log": {
                #"level": "debug"
                "level": "fatal"
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "listen": "127.0.0.1",
                    "listen_port": 20000
                }
            ],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "vless-out",
                    "server": ip,
                    "server_port": port,
                    "uuid": uuid
                }
            ],
            "dns": {
                "servers": [
                    {
                        "tag": "remote",
                        "type": "udp",
                        "server": "8.8.8.8",
                        "detour": "vless-out"
                    }
                ]
            }
        }
        if opt["type"] != "none" and opt["type"] != "tcp":
            config["outbounds"][0]["transport"] = {
                "type": opt["type"]
            }
        if opt["security"] == "tls" or opt["security"] == "reality":
            config["outbounds"][0]["tls"] = {
                "enabled": True,
                "server_name": opt["sni"],
                "insecure": opt["insecure"]
            }
            if "alpn" in opt:
                config["outbounds"][0]["tls"]["alpn"] = opt["alpn"].split(",")
            if "fp" in opt:
                if opt["fp"] == "":
                    config["outbounds"][0]["tls"]["utls"] = {
                        "enabled": True,
                        "fingerprint": "chrome"
                    }
                else:
                    config["outbounds"][0]["tls"]["utls"] = {
                        "enabled": True,
                        "fingerprint": opt["fp"]
                    }
            if opt["security"] == "reality":
                config["outbounds"][0]["tls"]["reality"] = {
                    "enabled": True
                }
                if "utls" not in config["outbounds"][0]["tls"]:
                    config["outbounds"][0]["tls"]["utls"] = {
                        "enabled": True,
                        "fingerprint": "chrome"
                    }
                if "pbk" in opt:
                    config["outbounds"][0]["tls"]["reality"]["public_key"] = opt["pbk"]
                if "sid" in opt:
                    config["outbounds"][0]["tls"]["reality"]["short_id"] = opt["sid"]
        if opt["flow"] == "xtls-rprx-vision":
            config["outbounds"][0]["flow"] = "xtls-rprx-vision"
        if opt["type"] == "httpupgrade":
            if "path" in opt:
                config["outbounds"][0]["transport"]["path"] = opt["path"]
            if "host" in opt:
                config["outbounds"][0]["transport"]["headers"] = {
                    "Host": opt["host"]
                }
        if opt["type"] == "grpc":
            if "serviceName" in opt:
                config["outbounds"][0]["transport"]["service_name"] = opt["serviceName"]
        if opt["type"] == "xhttp":
            if "path" in opt:
                config["outbounds"][0]["transport"]["path"] = opt["path"]
            if "host" in opt:
                config["outbounds"][0]["transport"]["headers"] = {
                    "Host": opt["host"]
                }
            if "mode" in opt:
                config["outbounds"][0]["transport"]["mode"] = opt["mode"]
            if "extra" in opt:
                config["outbounds"][0]["transport"]["extra"] = json.loads(opt["extra"])
            print("XHTTP-конфиг не поддерживается sing box, вычёркиваем...")
            continue

    if proto == "hy2" or proto == "hysteria2":
        config = {
            "log": {
                #"level": "debug"
                "level": "fatal"
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 20000
                }
            ],
            "outbounds": [
                {
                    "type": "hysteria2",
                    "tag": "hy2-out",
                    "server": ip,
                    "server_port": port,
                    "password": uuid,
                    "tls": {
                        "enabled": True,
                        "server_name": opt["sni"],
                        "insecure": opt["insecure"]
                    }
                }
            ],
            "dns": {
                "servers": [
                    {
                        "tag": "remote",
                        "type": "udp",
                        "server": "8.8.8.8",
                        "detour": "hy2-out"
                    }
                ]
            }
        }
        if "obfs-password" in opt:
            config["outbounds"][0]["obfs"] = {
                "type": opt["obfs"],
                "password": opt["obfs-password"]
            }

    # print(json.dumps(config))

    if not config:
        #print("Неизвестный протокол "+proto+". Вычёркиваем...")
        continue

    fo = open("config.json", "w")
    fo.write(json.dumps(config, indent=2))
    fo.close()

    cmd = [path_to_xray, "run", "-c", config_path]

    try:
        """process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )"""
        process = subprocess.Popen(cmd)

        # на инициализацию соединения
        time.sleep(3)

        #print(process.poll())
        print(f"Singbox запущен (PID: {process.pid})")
        try:
            proxy_ip = requests.get('https://api.ipify.org', proxies=proxies, timeout=10).text

            if proxy_ip != real_ip:
                print(f"IP изменился на: {proxy_ip}")
                print("Рабочий конфиг: "+link)
                with open("vald.txt", "a", encoding="utf-8") as valid:
                    valid.write(link+"\n")
                #print(requests.get("https://www.google.com/", proxies=proxies).content)
            else:
                print("IP не изменился. Трафик идет мимо прокси")
        except Exception as e:
            print(f"Нерабочий конфиг, вычёркиваем... (Ошибка: {e})")
        finally:
            process.terminate()
            process.wait()
            print("Singbox остановлен. Проверено "+str(count)+" из "+str(len(list))+" конфигов")
    except Exception as e:
        print(f"Ошибка при запуске Singbox: {e}")

print("Все "+str(count)+" конфигов проверены. Рабочие сохранены в valid.txt, ну а нерабочим земля пухом")