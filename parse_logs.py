import json

ips_blacklist = set()  # set of IPs found to be malicious
ua_blacklist  = list() # list so that later on we can count items that are added multiple times
ua_whitelist  = set()  # set of user_agents that are found to be benign

# load the json into logs object
logs = json.load(open("http.log"))

# iterate over entries and filter based on identified markers of IoC
for log in logs:
	if ("'" in log['uri'] or "'" in log['username'] or 
		"'" in log['user_agent'] or "<" in log['uri'] or 
		"<" in log['host'] or "pass" in log['uri'] or 
		":;" in log['uri'] or "};" in log['uri']):
		ips_blacklist.add(log['id.orig_h'])
		ua_blacklist.append(log['user_agent'])
		
# collect new malicious agents that match existing ones but not in ips_blacklist
for log in logs:
	if log['user_agent'] in ua_blacklist and log['id.orig_h'] not in ips_blacklist:
		ua_blacklist.append(log['user_agent'])

# identifiy agents that are found more than 9 times > those should be benign and can be whitelisted
m_counted = {x:ua_blacklist.count(x) for x in ua_blacklist}
for i in m_counted:
	if m_counted[i] >= 9:
		ua_whitelist.add(i)

# identify additional IPs that are in ua_blacklist and not in ua_whitelist and not in ip_blacklist 
for log in logs:
	if log['user_agent'] in ua_blacklist and log['user_agent'] not in ua_whitelist and log['id.orig_h'] not in ips_blacklist :
		ips_blacklist.add(log['id.orig_h'])

print(len(ips_blacklist))
# print out comma separated string for pastin into srf.elfu.org firewall for DENY
print(",".join(ips_blacklist))