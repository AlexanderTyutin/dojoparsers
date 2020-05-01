import re
from dojo.models import Endpoint, Finding

class XSStrikeParser(object):
	def __init__(self, reportfile, test):
		print("Loading file...")

		self.title = ""
		self.description = ""
		self.endpoint = ""
		self.severity = ""
		self.summary = ""
		self.cve = ""
		self.test = test

		self.data = reportfile.readlines()

		self.items = ()

		for dataline in self.data:
			self.parseLine(dataline)
			#print(dataline.strip())
		if self.severity != "":
			self.createFinding()


	def parseLine(self, line):
		# Checking for the new title
		if 'Vulnerable component:' in line:
			# Write data before creating new title
			if self.title != "":
				self.createFinding()
			# ------------------------------------
			# Clear old data
			self.title = ""
			self.description = ""
			self.endpoint = ""
			self.severity = ""
			self.summary = ""
			self.cve = ""
			# ------------------------------------
			# Save new title
			temps = re.search('(Vulnerable component:(.*))', line)
			self.title = temps.group(1).strip()
		else:
			# Checking for location
			if 'Component location:' in line:
				temps = re.search('(Component location:(.*))', line)
				self.description = temps.group(1).strip()
				self.endpoint = temps.group(2).strip()
			else:
				# Checking for Summary
				if 'Summary:' in line:
					if (self.summary != ""):
						self.createFinding()
						self.severity = ""
						self.cve = ""
					temps = re.search('(Summary:(.*))', line)
					self.summary = temps.group(2).strip()
				else:
					# Checking for Severity
					if 'Severity:' in line:
						temps = re.search('(Severity:(.*))', line)
						self.severity = temps.group(2).strip()
					else:
						# Checking for CVE
						if ' CVE: ' in line:
							temps = re.search('CVE:(.*)', line)
							self.cve = temps.group(1).strip()
							#self.createFinding()
							# Clear old data
							#self.severity = ""
							#self.summary = ""
							#self.cve = ""
							# ------------------------------------



	def createFinding(self):
		if (self.severity == ""):
			self.severity = "Info"
		if (self.summary == ""):
			self.summary = "Manual checking needed"
		if (self.cve != ""):
			self.cve = " | " + self.cve
		'''
		print("Title: " + self.title + self.cve)
		print("Description: " + self.description)
		print("Summary: " + self.summary)
		print("Severity: " + self.severity)
		#print("CVE: " + self.cve)
		'''
		striker_finding = Finding(title=self.title,
									test = self.test,
									active=False,
									verified=False,
									description=self.description + self.endpoint,
									severity = self.severity,
									numerical_severity = Finding.get_numerical_severity(self.severity))
		self.items.append(striker_finding)


if __name__ == "__main__":
	xs = XSStrikeParser(open("FILENAME_HERE", 'r'), None)
	'''
	print("Debugging XSStrikeParser")
	filename = "FILENAME_HERE"
	testfile = open(filename, 'r')
	reportlines = testfile.readlines()

	vTitle = ""
	vDescription = ""
	vEndpoint = ""
	vSeverity = ""
	vSummary = ""
	vCVE = ""

	checker = 0

	for line in reportlines:
		if '------------------' in line:
			continue

		if vCVE != "":
			print("Title: " + vTitle + " | " + vCVE)
			print("Description: " + vDescription)
			print("Summary: " + vSummary)
			print("Severity: " + vSeverity)
			print("CVE: " + vCVE);
			print('----------------------------------')
			vSummary = ""; vSeverity = ""; vCVE = "";
			#if '------------------' in line:
				#vDescription = "";


		# Checking for title
		if 'Vulnerable component:' in line:
			temps = re.search('(Vulnerable component:(.*))', line)
			vTitle = temps.group(2).strip()
		# Checking for location
		if 'Component location:' in line:
			temps = re.search('(Component location:(.*))', line)
			vDescription = temps.group(1).strip()
			vEndpoint = temps.group(2).strip()
		# Checking for Summary
		if 'Summary:' in line:
			temps = re.search('(Summary:(.*))', line)
			vSummary = temps.group(2).strip()
		# Checking for Severity
		if 'Severity:' in line:
			temps = re.search('(Severity:(.*))', line)
			vSeverity = temps.group(2).strip()
		# Checking for CVE
		if ' CVE: ' in line:
			temps = re.search('CVE:(.*)', line)
			vCVE = temps.group(1).strip()
	'''
