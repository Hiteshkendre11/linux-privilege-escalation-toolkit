import os
import grp





uid = os.getuid()
print("User ID:", uid)


if uid == 0:
    print("Privilege:", "Root")


else :
        print("Privilege:", "Non-root")

username = os.environ.get("USER")
print("Username:", username)


gids = os.getgroups()
print("Groups:")


for gid in gids:
    group = grp.getgrgid(gid)
    print(" -", group.gr_name)


kernel = os.uname().release
print("Kernel:", kernel)


os_info = {}


with open("/etc/os-release") as file:
     for line in file:
         line = line.strip()
         if "=" in line:
            key, value = line.split("=", 1)
            os_info[key] = value.strip('"')

print("OS:", os_info.get("PRETTY_NAME"))
print("Version:", os_info.get("VERSION_ID"))
print("Codename:", os_info.get("VERSION_CODENAME"))

