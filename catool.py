#! /usr/bin/env python

import sys, logging, os, stat, urllib, urllib2, subprocess, getopt, optparse, shutil, platform, getpass
import sys
import base64, json # for jira rest

def missingModule(module, usage):
	print "This application requires the python %s module to %s" % (module, usage)
	print "Typically %s can be installed through 'apt-get install python-%s' or 'easy_install %s'" % (module, module)
	print "apt-get is preferred for HP Cloud Systems"
	exit()
#We don't expect to find these and should tell the user that they need to get fetch them manually
try:
	import mechanize
except:
	missingModule("mechanize", "access web-servers as a client, using cookies and html parsing.")
	
try:
	import M2Crypto
except:
	missingModule("m2crypto", "unpack x509 certificates.")


class Settings():
	JIRA_HOST = "https://jira.hpcloud.net/rest/api/2/issue/"
	PUB_CA = False
	CA_Options = [
		{"ID":0, "Scope":"Private", "Method":"ADCS", "Zone":"DEPRECATED", "Env":"DEPRECATED", "URL":"manual-ca.las.hpcloud.ms", "ST":"Nevada", "L":"Las Vegas"},
		{"ID":1, "Scope":"Private", "Method":"ADCS", "Zone":"AW2AZ1", "Env":"Production", "URL":"aw2cloudica01.uswest.hpcloud.ms", "ST":"Nevada", "L":"Las Vegas"},
		{"ID":2, "Scope":"Private", "Method":"ADCS", "Zone":"AW2AZ2", "Env":"Production", "URL":"aw2cloudica02.uswest.hpcloud.ms", "ST":"Nevada", "L":"Las Vegas"},
		{"ID":3, "Scope":"Private", "Method":"ADCS", "Zone":"AW2AZ3", "Env":"Production", "URL":"aw2cloudica03.uswest.hpcloud.ms", "ST":"Nevada", "L":"Las Vegas"},
		{"ID":4, "Scope":"Private", "Method":"ADCS", "Zone":"AW1", "Env":"NonProduction", "URL":"aw1cloudica01.uswest.hpcloud.ms", "ST":"Nevada", "L":"Las Vegas"},
		{"ID":5, "Scope":"Private", "Method":"ADCS", "Zone":"AE1AZ1", "Env":"Production", "URL":"ae1cloudica01.useast.hpcloud.ms", "ST":"Virginia", "L":"Reston"},
		{"ID":6, "Scope":"Private", "Method":"ADCS", "Zone":"AE1AZ2", "Env":"Production", "URL":"ae1cloudica02.useast.hpcloud.ms", "ST":"Virginia", "L":"Reston"},
		{"ID":7, "Scope":"Private", "Method":"ADCS", "Zone":"AE1AZ3", "Env":"Production", "URL":"ae1cloudica03.useast.hpcloud.ms", "ST":"Virginia", "L":"Reston"},
		{"ID":8, "Scope":"Public", "Method":"HPDB", "Zone":"PUBLIC", "Env":"Both", "URL":"Verisign Public CA. Supported globally and required for customer facing systems. Expensive to issue", "OU":"HPCS", "ST":"Washington", "L":"Seattle"},
        {"ID":9, "Scope":"OnCloud", "Method":"ADCS", "Zone":"ONCLOUD", "Env":"OnCloud", "URL":"sec-oncloud-ica.hpcloud.ms", "ST":"Washington", "L":"Seattle"},
        {"ID":10, "Scope":"Dakar", "Method":"ADCS", "Zone":"DAKAR", "Env":"OnCloud", "URL":"OPS-AE1AZ1-ICA1.dakar.hpcloud.net", "ST":"Washington", "L":"Seattle"},
		{"ID":11, "Scope":"Public", "Method":"HPDB", "Zone":"PUBLIC_HBFIX", "Env":"Both", "URL":"Public Certificate for Heartbleed replacement certificates", "OU":"HBReplacement", "ST":"Washington", "L":"Seattle"},

	]
	
	def defaults(self):
		self.CONF_DIR = os.path.expanduser("~") + "/.catool"

	def load(self, filePath):
		print "Settings file loading not implemented yet"

	def printCA(self):
		print "ID\tZone\tEnvironment\tURL"
		for option in self.CA_Options:
			print "%i\t%s\t%s\t%s" % (option['ID'], option['Zone'], option['Env'], option['URL'])

	def setCA(self, ca_string):
		try:
			if ca_string.isdigit():
				self.ca = [k for k in self.CA_Options if k['ID'] == int(ca_string)][0]
			else:
				str = ca_string.upper()
				self.ca = [k for k in self.CA_Options if k['Zone'] == str or k['URL'] == str][0]
		except:
			print "%s Not a valid Certificate Authority Identifier" % ca_string
			self.printCA()
			raise Exception("Require a valid CA to use")
		
		return self.ca
	
	def getUrl(self, target):
		return "https://%s/certsrv/%s" % (self.ca['URL'], target)
	
	def getJiraHost(self):
		return self.JIRA_HOST
   
	def __init__(self):
		self.defaults()
		
class JiraRestClient():
	def __init__(self, host, user, passw):     
		self.jirahost = host
		self.username = user
		self.password = passw
 
	def createIssue (self, project, summary, problem, issue_type=3, priority=3):
		#issuetype id = 1=Bug, 2=Feature, 3=Task, 4= Improvement, 5=Query - not all types available in all projects, will throw bad request
		#priority id = 1=Blocker,2=Critical,3=Major,4=Minor,5-Trivial 
		ticketdata = {
			"fields": {
				"project": {
					"key": project
				},
				"summary": summary,
				"description": problem,
				"issuetype": {
					"id": str(issue_type)
				},
				"priority": {
					"id": str(priority)
				}
			}
		} 

		req = urllib2.Request(self.jirahost, json.dumps(ticketdata))
		req.add_header("Content-Type", "application/json")
		req.add_header('Authorization', 'Basic %s' % base64.b64encode('%s:%s' % (self.username, self.password)))
		try:
			response = json.loads(urllib2.urlopen(req).read())

			if response.has_key("key"):
				return response["key"]
		except:
			raise Exception("[E] Could not create ticket")

logger = logging.getLogger("mechanize")
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)

notificationIDs = []
settings = None
auto_client = """
HOME                    = .
RANDFILE                = $ENV::HOME/.rnd

[ req_distinguished_name ]
C = US
ST = ##STATE##
L = ##LOCATION##
O = Hewlett-Packard
OU = Cloud Services
CN = ##CN##
emailAddress = ##EMAIL##

[ req ]
prompt                  = no
default_bits            = 1024
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
req_extensions          = v3_req
string_mask = nombstr

[ usr_cert ]
basicConstraints=CA:FALSE
nsCertType                      = client
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage=clientAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer:always
"""

auto_server = """
HOME                    = .
RANDFILE                = $ENV::HOME/.rnd

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
##SUBJALT##

[ req_distinguished_name ]

C = US
ST = ##STATE##
L = ##LOCATION##
O = Hewlett-Packard
OU = Cloud Services
CN = ##CN##
emailAddress = ##EMAIL##

[ req ]
prompt = no
default_bits            = 1024
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
req_extensions          = v3_req
string_mask = nombstr

[alt_names]
##ALTNAMES##

[ usr_cert ]
basicConstraints=CA:FALSE
nsCertType                      = server
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer:always

"""

auto_pub_client = """
HOME                    = .
RANDFILE                = $ENV::HOME/.rnd

[ req_distinguished_name ]
C=US
ST=##STATE##
L=##LOCATION##
O=Hewlett-Packard
OU=HPCS
CN=##CN##
emailAddress = ##EMAIL##

[ req ]
prompt                  = no
default_bits            = 1024
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
req_extensions          = v3_req
string_mask = nombstr

[ usr_cert ]
basicConstraints=CA:FALSE
nsCertType                      = client
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage=clientAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer:always
"""

auto_pub_server = """
HOME                    = .
RANDFILE                = $ENV::HOME/.rnd

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier = hash
##SUBJALT##

[ req_distinguished_name ]

C=US
ST=##STATE##
L=##LOCATION##
O=Hewlett-Packard
OU=##OU##
CN=##CN##
emailAddress=##EMAIL##

[ req ]
prompt = no
default_bits            = 1024
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
req_extensions          = v3_req
string_mask = nombstr

[alt_names]
##ALTNAMES##

[ usr_cert ]
basicConstraints=CA:FALSE
nsCertType                      = server
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer:always

"""

prompt = True

# Setup the directory structure required for this tool
def setup():
	if os.path.exists(settings.CONF_DIR):
		print "Setup found a working directory called %s" % settings.CONF_DIR
		print "If you wish to overwrite you must delete this manually and then run setup"
		return

	#TODO: Verify / make windows version work
	os.makedirs(settings.CONF_DIR)
	os.makedirs(settings.CONF_DIR + "/cookies")
	os.makedirs(settings.CONF_DIR + "/certificates")
	os.makedirs(settings.CONF_DIR + "/certificates/temp")
	os.chmod(settings.CONF_DIR, stat.S_IRWXU)

	sLoc = settings.CONF_DIR + "/" + "auto_server.cnf"
	cLoc = settings.CONF_DIR + "/" + "auto_client.cnf"
	psLoc = settings.CONF_DIR + "/" + "auto_pub_server.cnf"
	pcLoc = settings.CONF_DIR + "/" + "auto_pub_client.cnf"

	try:
		sFile = open(sLoc, "wb")
	except:
		print "Could not create file %s" % sLoc
		exit()
	
	try:
		cFile = open(cLoc, "wb")
	except:
		print "Could not create file %s" % cLoc
		exit()
		
	try:
		psFile = open(psLoc, "wb")
	except:
		print "Could not create file %s" % psLoc
		exit()
	
	try:
		pcFile = open(pcLoc, "wb")
	except:
		print "Could not create file %s" % pcLoc
		exit()

	sFile.write(auto_server)
	cFile.write(auto_client)
	psFile.write(auto_pub_server)
	pcFile.write(auto_pub_client)

	sFile.close()
	cFile.close()
	psFile.close()
	pcFile.close()

# Extract the Common Name from given certificate data.
def CNFromCert(certificate):
	cert = M2Crypto.X509.load_cert_string(certificate)
	sub = cert.get_subject().as_text()
	cn = sub.split("CN=")[1].split("/")[0]
	return cn

# Attempt to download a certificate from the CA based on the Certificate Number given during submission.
def fetchCertificate(cID):
	#url = settings.CA_URL + "certnew.cer?ReqID=%s&Enc=b64" % cID 
	url = settings.getUrl("certnew.cer?ReqID=%s&Enc=b64" % cID) 
	req = urllib2.Request(url, None)
	response = urllib2.urlopen(req)
	certificate = response.read()
	if "Contact your administrator" in certificate:
		print "[E] Could not fetch certificate ID %s" % cID
	else:

		cn = CNFromCert(certificate)
		#Put certificate file in the correct directory
		fileName = settings.CONF_DIR + "/certificates/" + cn + "/" + cID + ".cer"
		fout = None
		try:
			fout = open(fileName, "wb")
		except:
			fileName = settings.CONF_DIR + "/certificates/temp/" + cID + ".cer"
			fout = open(fileName, "wb")
			
		fout.write(certificate)
		fout.close()
		
		print "[I] Downloaded certificate [%s] to %s" % (cn, fileName)

# Submits all stored cookies to the CA and downloads any certificates offered by the CA.
def checkCAForCerts():
	#Load Cookies
	cj = mechanize.LWPCookieJar()
	opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(cj))
	mechanize.install_opener(opener)

	try:	
		cj.load(filename=settings.CONF_DIR + "/cookies/db", ignore_discard=True, ignore_expires=True)
	except:
		print "[W] Could not load cookies from database, have you submitted any CSRs? If you have its possible you've cleaned out your cookies already"
		return

	print settings.getUrl('')
	br = mechanize.Browser()
	br.set_cookiejar(cj)
	# br.open(settings.ca['URL'])
	br.open(settings.getUrl('Default.asp'))
	r1 = br.follow_link(text_regex=r"View the status of a pending certificate request")
	
	#Some condition that checks for no certificates.
	#Grok for the "(checkPending2()" line
	certNum = []
	for line in r1.readlines():
		if "OnClick=\"CheckPending2" in line:
			certNum.append(line.strip().split("'")[1])

	#Cookie Stuff, used for Deny / Pending
	for num in certNum:
		print "\n[I] Attempting to fetch certificate number: %s" % num
		# br.open(settings.ca['URL'] + "certckpn.asp")
		br.open(settings.getUrl("certckpn.asp"))
		br.select_form(name='SubmittedData')
		br.set_all_readonly(False)
		br["Mode"] = 'chkpnd'
		br["ReqID"] = num
		br["TargetStoreFlags"] = ""
		br["SaveCert"] = "Yes"

		response = br.submit()
		for line in response.readlines():
			if "Denied" in line:
				print "[I] The Certificate Signing Request was denied or the certificate was issued and has been revoked."
				break

			if "Pending" in line:
				print "[I] The Certificate Signing Request is still pending."
				break

			if "certificate you requested was issued to you" in line:
				print "[I] The Certificate Signing Request was approved"	
				fetchCertificate(num)
				break
							
	if len(certNum) == 0:
		print "Can't find any certificates for the cookies you have saved. Sorry."


def sendNotification(jc, settings, options, csrFile):
	if settings.ca['Scope'] == 'Private':
		if len(notificationIDs) == 0:
			print 'No Notification was sent because Certificate Submission appeared to fail'
			print 'If you require further assistance please email hpcs.security@hp.com'
			return
		text = "Certificate Submission to %s\n" % settings.getUrl("")
		text += "Certificate ID's \n"
		if len(notificationIDs) == 1:
			print "[i] 1 Request:"
			summary = "1 Certificate Request Submitted to %s" % settings.ca['Zone']
		else:
			print "[i] %i Requests:" % len(notificationIDs)
			summary = "%i Certificate Requests Submitted to %s" % (len(notificationIDs),settings.ca['Zone'])
		for ID in notificationIDs:
			text += "%s \n" % ID
			print ID
	
		
		
		try:
			ret = jc.createIssue("SEC", summary, text, issue_type='3')
			print "\n[i] The security team have been notified re your certificate request(s) : https://jira.hpcloud.net/browse/%s" % ret
		except:
			print "\n[E] Cannot create ticket, please manually create a ticket on SEC stating the CA you have submitted the request to, the request number and your contact email address."
         
	elif settings.ca['Scope'] == 'Public':
		assert(settings.ca['Method'] == 'HPDB')
		fo = open(csrFile)
		csr = fo.read()
		fo.close()
		
		summary = "Public Certificate Request Submitted\n"
		if settings.ca['Zone'] == 'PUBLIC_HBFIX':
			text = "Please request a public certificate for user %s using HP Heartbleed recovery site https://g4t0070.houston.hp.com/hp/client/sslPublicStart.php\n" % options.notify
		else:
			text = "Please request a public certificate for user %s using HP DigitalBadge http://intranet.hp.com/HPIT/GetIT/DigitalBadge/Pages/PublicCert.aspx\n" % options.notify 
		if options.client_cname:
			text += "User has requested a client cert for: %s\n" % options.client_cname
		else:
			text += "User has requested a server cert for: %s\n" % options.server_cname
		text += "\nEnter \"HPCS-Cert-Managers\" for Enterprise Directory Global Group.\n"
		if options.sans:
			text += "\nUser has requested the following SANs, these must be submitted into the DigitalBadge site during the enrollment process:\n"
			for san in options.sans.split(","):
				text += "%s \n" % san
		text += "\nTo revoke this certificate, visit https://g2t0066.austin.hp.com/hp/client/userTools.php\n"
		text += "\n\n"
		text += csr
		try:
        		ret = jc.createIssue("SEC", summary, text, issue_type='3')
			print "\n[i] The security team have been notified re your certificate request(s) : https://jira.hpcloud.net/browse/%s" % ret
		except:
			print "\n[E] Cannot create ticket, please manually create a ticket on SEC stating the CA you have submitted the request to, the request number and your contact email address."
		

# sans is only used when we're given a CSR that does not contain SAN information, typically from the ESKM
# 
def submitCSR(csrFile, attributes):
	fo = open(csrFile)
	csr = fo.read()
	fo.close()

	cj = mechanize.LWPCookieJar()
	opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(cj))
	mechanize.install_opener(opener)
	
	try:	
		cj.load(filename=settings.CONF_DIR + "/cookies/db", ignore_discard=True, ignore_expires=True)
	except:
		#We don't care if we fail to load the cookies for submission
		pass
		

	br = mechanize.Browser()
	br.set_cookiejar(cj)
	try:
		br.open(settings.getUrl("certrqxt.asp"))
	except Exception, e:
		print "CATool cannot reach CA server: %s: %s" % (settings.getUrl("certrqxt.asp"), e)
		print "Please check that you're able to access the CA. You may need to be on the VPN and turn off any annoying proxy"
		print "See Troubleshooting on https://wiki.hpcloud.net/display/csbu/catool"
		return
	
	formData = {}	
	formData['Mode'] = "newreq"
	formData['CertRequest'] = csr
	formData['CertAttrib'] = "UserAgent%3AMozilla%2F5.0+%28Windows+NT+6.1%3B+WOW64%3B+rv%3A8.0%29+Gecko%2F20100101+Firefox%2F8.0%0D%0A"
	#TODO: Set a realistic date
	formData['FriendlyType'] = "Saved-Request+Certificate+%2822+December+2011+08%3A21%3A04%29"
	formData['ThumbPrint'] = ""
	formData['TargetStoreFlags'] = "0"
	formData['SaveCert'] = "yes"
	if attributes != None:
		formData['CertAttrib'] = attributes

	formValues = urllib.urlencode(formData)
	
	# url = settings.ca['URL'] + "certfnsh.asp"
	url = settings.getUrl("certfnsh.asp")
	req = urllib2.Request(url, formValues)

	response = mechanize.urlopen(req)
	
	cookieText = response.info().getheader('Set-Cookie')
	for line in response.readlines():
		if "Your Request Id" in line:
			print "[I] " + line
			#notificationIDs.append(line)
			notificationIDs.append("%s : %s" % (line.strip(), csrFile.split(".csr")[0]))
			break

	cj.extract_cookies(response, req)
	try:
		cj.save(settings.CONF_DIR + "/cookies/db", ignore_discard=True, ignore_expires=True)
	except:
		print "[E] Unable to save cookies, your CSR has been submitted but catool will not be able to retrieve the certificate or check on its status"


def checkConstraints(cname, email, ctype, sans=[]):
	allowedNames = ['hpcloud.net', 'hpcloud.com']
	if ctype == "Server":
		if cname[-11:] not in allowedNames:
			return False

		for x in sans:
			if x[-11:] not in allowedNames:
				return False
	else:
		return False
	return True

def which(program, append_exe=True):
	system = platform.system()	
	
	#Unix Path Delimiter
	delim = ':'

	if system == "Windows":
		if append_exe == True:
			program = program + ".exe"
		delim = ';' # Windows Path Delimiter
		

	for path in os.environ.get('PATH', '').split(delim):
		if os.path.exists(os.path.join(path, program)) and \
			not os.path.isdir(os.path.join(path, program)):
			
			return os.path.join(path, program)
	return None


def genCSR(ctype, cname, email, state, location, orgunit, sans=[]):
	print orgunit
	#extended for public server
	ctypes = {'server':'/auto_server.cnf',
			'pub_server':'/auto_pub_server.cnf',
			'pub_client':'/auto_pub_client.cnf',
			'client':'/auto_client.cnf'}
	
	if ctype not in ctypes:
		raise Exception("genCSR called with incorrect ctype")

	workingPath = settings.CONF_DIR + "/certificates/"
	try:
		workingPath = workingPath + cname + "/"
		os.makedirs(workingPath)
	except:
		raise Exception("Working path %s already exists, cannot create duplicates. Delete %s if you wish to request a new certificate for this common name" % (workingPath, workingPath))
	
	if not os.path.exists(workingPath):
		print "[E] Cannot find a working path, has catool been setup correctly?"
		raise Exception("Cannot find a working path") 
	
	print "[I] Certificate Working Path %s" % workingPath
	
	tFile = None
	#extended for public server
	try:
		tFile = open(settings.CONF_DIR + ctypes[ctype])
	except:
		print "[E] Error cannot read config, please delete .catool directory and re-run catool.py --setup"
		exit(1)
	
	oFile = open(workingPath + cname + ".cnf", "wb")
	for line in tFile.readlines():
		if len(sans) > 0:
			if "##ALTNAMES##" in line:
				counter = 1
				for x in sans:
					prefix = "DNS.%i = " % (counter)
					counter = counter + 1
					oFile.write(prefix + x + "\n") 
				continue
			if "##SUBJALT##" in line:
				oFile.write("subjectAltName = @alt_names\n")
				continue

		if "##CN##" in line:
			oFile.write("CN = " + cname + "\n")
			continue

		if "##EMAIL##" in line:
			oFile.write("emailAddress = " + email + "\n")
			continue
		
		if "##STATE##" in line:
			oFile.write("ST = " + state + "\n")
			continue
		
		if "##OU##" in line:
			oFile.write("OU = " + orgunit + "\n")
			continue

		if "##LOCATION##" in line:
			oFile.write("L = " + location + "\n")
			continue
		

		oFile.write(line)

	tFile.close()
	oFile.close()
	
	openssl = which("openssl")

	if not openssl:
		raise Exception("OpenSSL not installed or not in system PATH")
	
	pathCN = workingPath + cname
	keyFile = pathCN + ".key"
	csrFile = pathCN + ".csr"
	cnfFile = pathCN + ".cnf"
	args = ['req', '-new', '-sha1', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', csrFile, '-config', cnfFile]
	command = [openssl]
	command.extend(args)
	
	try:
		subprocess.check_call(command, shell=False, env=os.environ)
	except:
		raise Exception("[E] Call to openssl failed")

	return pathCN + ".csr"

def cleanCookies():
	cfile = settings.CONF_DIR + "/cookies/db"
	try:
		os.remove(cfile)
	except:
		print "[W] Could not delete cookies file: %s" % cfile

def main():
	global settings
	settings = Settings()
	parser = optparse.OptionParser()
	modes = optparse.OptionGroup(parser, "Modes of operation", "One of these options must be selected")
	modes.add_option("--setup", action="store_const", const="setup", dest="mode", help="Setup CA Tool directory structure")
	modes.add_option("--client", action="store", dest="client_cname", help="Submit a Client CSR with CNAME")
	modes.add_option("--server", action="store", dest="server_cname", help="Submit a Server CSR with CNAME")
	modes.add_option("--fetch", action="store", dest="fetch", help="Fetch a specific certificate number from the CA")
	modes.add_option("--fetch-all", action="store_const", const="fetch-all", dest="mode", help="Fetch all certificates with cookies saved by catool")
	modes.add_option("--csr", action="store", dest="csrFile", help="Submit csr in FILE to CA for signing", metavar="FILE")
	modes.add_option("--clean-cookies", action="store_const", const="clean", dest="mode", help="Clear out cookies used for tracking. This will stop the tool from downloading all the certificates you have requested previously")
	modes.add_option("--purge", action="store_const", const="purge", dest="mode", help="Delete all stored cookies, CSRs, Private Keys and Certificates")
#	modes.add_option("--batch", action="store", dest="batchfile", help="File containing CNAMEs for individual Certificates")

	req = optparse.OptionGroup(parser, "Mandatory Certificate Fields", "These options must be selected to submit a CSR")
	req.add_option("--email", action="store", dest="email", help="Email address for Certificate Information, preferably a team/distro address")
	req.add_option("--ca", action="store", dest="ca", help="Specify CA by ID, Zone or address", metavar="1, AZ1, awcloudica2.uswest.hpcloud.com")
	
	opt = optparse.OptionGroup(parser, "Optional Certificate Fields")
	opt.add_option("--san", action="store", dest="sans", help="Add Subject Alternative Name. Seperate multiple sans using ,")
	opt.add_option("--attrib", action="store", dest="attrib", help="Use to add additional attributes to the certificate request")	
	opt.add_option("--list-ca", action="store_const", const="x", dest="listca", help="Print a list of the currently configured CAs")

	optional = optparse.OptionGroup(parser, "Other Options", "Optional fields, not required but may be desirable")
	optional.add_option("-y", dest="prompt", help="Assume 'Yes' is the answer to all questions", action="store_false", default=True)
	optional.add_option("--no-submit", action="store_const", const="x", dest="nosubmit", help="Generate the CSR but do not submit it")	

		
	notify = optparse.OptionGroup(parser, "Notification Options", "Notify the security team of cert requests via Jira")
	notify.add_option("--notify", action="store", dest="notify", help="Use the Jira server for Notification, where \'NOTIFY\' is your jira username")	

	parser.add_option_group(req)
	parser.add_option_group(opt)	
	parser.add_option_group(optional)
	parser.add_option_group(modes)
	parser.add_option_group(notify)

	options, args = parser.parse_args()

	workingPath = settings.CONF_DIR
	csrFiles = []

	try:
		os.stat(workingPath)
	except:
		if options.mode != "setup":
			print "Cannot find working path for catool. Have you run setup?"
			parser.print_help()
			exit()	

	if options.listca:
		settings.printCA()
		exit(0)

	if options.mode == "setup":
		setup()
		exit(0)

	if options.mode == "clean":
		if options.prompt:
			print "[W] This operation will remove all saved cookies. Doing so removes all history information used by this tool."
			print "[W] You will not be able to automatically retrieve certificates generated before the clean operation."
			print "[I] Certificates can still be fetched by requesting specific numbers using the --fetch and --num options."
			answer = raw_input("[Q] Confirm Delete All Certificates?...(y/N)")
			if answer == 'y' or answer == 'Y':
				cleanCookies()    
				print ("[I] Cookies Deleted")
		else:
			cleanCookies()
		exit(0)



	if options.ca:
		settings.setCA(options.ca)
		#if using the public CA (which cannot be automatically submitted to), set no-submit and notify to force creation of a jira ticket.
		if settings.ca['Scope'] == 'Public':
			assert(settings.ca['Method'] == 'HPDB')
			options.nosubmit = True
			if not options.notify:
				print ("** Public CA selected, cannot automatically submit to this CA.\n")
				print ("** You've requested a publicly signed certificate. These cannot be automatically requested from the CA.")
				print ("** ca-tool will generate a CSR for you and upload it to Jira as a request to the Security Team to create you a certificate")
				print ("** in order to do this, please re-run ca-tool using the --notify <your@email> option, as the jira ticket will be created in your name")
				exit(0)
	else:
		#No CA was provided *AND* listca was not invoked
		print "You must provide a valid CA to use by invoking the --ca option. If you're not sure which to use, use --list-ca to view a list"
		exit(0)

	if options.client_cname and options.server_cname:
		print "Cannot create a certificate for Client and Server at the same time"
		parser.print_help()
		exit()

	if options.notify:
		print "Please enter the jira password for user %s :" % options.notify
		userPass = getpass.getpass() 

	if options.client_cname:
		if settings.ca['Scope'] == 'Public':
			options.mode = "pub_client"
		else:	
			options.mode = "client"

	if options.server_cname:
		if settings.ca['Scope'] == 'Public':
			options.mode = "pub_server"
		else:	
			options.mode = "server"
		#If there's no "," in the string, the split will return the whole 
		cnames = options.server_cname.split(",")
		assert(len(cnames) > 0)
		if len(cnames) == 1:
			try:
				fp = open(options.server_cname, 'rb')
				for name in fp.readlines():
					if len(name.strip()) > 6:
						cnames.append(name.strip())
				fp.close()
			except:
				#Basically, we don't know if we've been given a cname or a file name. It's easier to try to open a file on disk, if that fails we assume it's a cname.
				#This is probably a dumb way to do things.
				#TODO: Add another server mode so we can do-away with this
				pass

	if options.fetch:
		options.mode = "fetch"

	if options.prompt:
		prompt = options.prompt		

	if options.csrFile:
		options.mode = "csr"

	if not options.mode:
		print "You must select a mode of operations"
		parser.print_help()
		exit()

	if options.server_cname:
		if not options.email:
			print "You must specify an email address, please use the help"
			return
		
		#if using the public CA, do not write SANs into the CSR file, as required by HP DigitalBadge docs. <-- Stoopid Digital Badge.
		if not options.sans:
			_sans = []
		elif options.sans:
			_sans = options.sans.split(",")
		for cname in cnames:
			print cname
			try:
				if settings.ca['Scope'] == 'Public': #Don't put the SAN in the CSR.
					csrFiles.append(genCSR(options.mode, cname, options.email, settings.ca['ST'], settings.ca['L'], settings.ca['OU']))
				else:
					csrFiles.append(genCSR(options.mode, cname, options.email, settings.ca['ST'], settings.ca['L'], "Cloud Services", sans=_sans))
			except Exception, e:
				print "[E]" + " ".join(e.args)
				exit(0)
		
		for csrFile in csrFiles: 
			print "[I] CSR Generated and saved to %s" % csrFile
			if not options.nosubmit and settings.ca['Method'] == 'ADCS':
				submitCSR(csrFile, options.attrib)
		
	if options.client_cname:
		if not options.email:
			print "[E] You must specify an email address, please use the help"
			return		

		if options.sans:
			print "[E] You cannot use Subject Alternative Names with client certificates"
			return
		#modified first option to tell it if its a public or normal server
		csrFile = genCSR(options.mode, options.client_cname, options.email, settings.ca['ST'], settings.ca['L'], "Cloud Services" )
		print "[I] CSR Generated and saved to %s" % csrFile
		if not options.nosubmit and settings.ca['Method'] == 'ADCS':
			submitCSR(csrFile, options.attrib)

	if options.mode == "fetch-all":
		checkCAForCerts()

	if options.mode == "fetch":
		fetchCertificate(options.fetch)
	
	if options.mode == "csr":
		if options.server_cname or options.client_cname or options.email or options.sans:
			print "[E] You cannot provide certificate parameters when using an existing CSR file, please use either --server or --client"
			return
		else:
			submitCSR(options.csrFile, options.attrib)

	if options.mode == "purge":
		print "[E] This code is not implemented yet, remove /home/<user>/.catool to set everything back to defaults"


	#Right at the end, send notifications if we have to
	if options.notify:
		jc = JiraRestClient(settings.getJiraHost(), options.notify, userPass)
		if settings.ca['Scope'] == 'Public':
				sendNotification(jc, settings, options, csrFile)
		else:
			sendNotification(jc, settings, options, None)
			
if __name__ == "__main__":
	main()	
