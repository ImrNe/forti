import re

# Read input from input.txt
with open("input.txt", "r") as file:
    lines = file.readlines()

# Initialize variables to store policy data
policies = []
policy = {}
current_line = 0

# Define a function to add missing properties with empty string
def add_missing_properties(policy):
    missing_properties = ["av-profile", "dnsfilter-profile", "ips-sensor", "application_list",
                          "webfilter-profile", "file-filter-profile", "ssl-ssh-profile"]
    for prop in missing_properties:
        if prop not in policy:
            policy[prop] = ""

# Loop through lines to parse policies
while current_line < len(lines):
    line = lines[current_line].strip()
    match = re.match(r'edit (\d+)', line)
    
    if match:
        policy_id = int(match.group(1))
        policy = {"policyid": policy_id}
        current_line += 1
        while current_line < len(lines):
            line = lines[current_line].strip()
            if line == "next":
                current_line += 1
                break
            key, value = line.split(None, 1)
            if key == "set":
                if value.startswith("uuid"):
                    current_line += 1
                    continue
                subkey, subvalue = value.split(None, 1)
                if subkey in ["srcintf", "dstintf", "srcaddr", "dstaddr"]:
                    if subkey not in policy:
                        policy[subkey] = []
                    items = subvalue.strip('"').split()
                    for item in items:
                        policy[subkey].append({"name": item})
                elif subkey == "service":
                    if subkey not in policy:
                        policy[subkey] = []
                    items = subvalue.strip('"').split()
                    for item in items:
                        policy[subkey].append({"name": item})
                else:
                    policy[subkey] = subvalue.strip('"')
            current_line += 1
        add_missing_properties(policy)
        policies.append(policy)

# Write output to output.txt
with open("output.txt", "w") as file:
    for policy in policies:
        file.write("- policyid: {}\n".format(policy["policyid"]))
        file.write("  name: \"{}\"\n".format(policy.get("name", "")))
        file.write("  action: {}\n".format(policy.get("action", "")))
        file.write("  logtraffic: {}\n".format(policy.get("logtraffic", "all")))
        file.write("  nat: disable\n")
        for prop in ["srcintf", "dstintf", "srcaddr", "dstaddr", "service"]:
            if prop in policy:
                file.write("  {}: \n".format(prop))
                for item in policy[prop]:
                    file.write("    - name: \"{}\"\n".format(item["name"]))
        for prop in ["av-profile", "dnsfilter-profile", "ips-sensor", "application_list",
                     "webfilter-profile", "file-filter-profile", "ssl-ssh-profile"]:
            file.write("  {}: {}\n".format(prop, policy.get(prop, "")))
        file.write("  changed: false\n")
