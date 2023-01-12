import subprocess

# ex: create_item("cli-tests", "Netflix", "login", "'password=12345' 'username=abc' 'Subscription Renewal Date[date]=2023-12-31'")
def create_item(vault, title, category, data):
    try:
        cmd = "op item create --vault %s --title %s --category %s %s" % (vault, title, category, data)
        res = subprocess.check_output(cmd, shell=True)
        print(res)
    except:
        print("error...")

