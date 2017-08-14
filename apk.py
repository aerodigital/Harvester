from harvester import harvester
from locator import locator
import re
from threading import Thread
import os
from filebro import getapks, getfolders, comparedir

class apk(object):
#TODO: Make this area threadable

	def __init__(self, folder):
		self.harvester = harvester()
		self.folder = folder
		#get subfolders, these are all targets for start()
		self.folders = getfolders(self.folder)
		self.batch = []
		for i in self.folders:
			if os.path.isdir(i):
				self.batch.append(getapks(i))
		#menu()
		#self.scan()

	def menu(self):
		raw_input(
		'''Choose an option:
		1.Settings
		2.File/Package operations
		3.Information Gathering
		4.Threat Modeling
		5.Vulnerability Analysis
		6.Scan and report folders

		'''
		)

	def start(self):
		for i in self.batch:
			self.harvester.baksmali(i)
			self.harvester.debugapk(i)
			self.harvester.dex(i)
			self.harvester.rebuild(i)

	def scan(self):
		for i in self.folders:
			print "Scanning: ", i
			loc = locator(i)
			loc.look(i)

	def recode(self):
		num = 1
		for i in self.folders:
			#make menu
			print str(num) + "- "
			for x in getfolders(i):
				print x
			num += 1

apk1 = apk("~/harvester/test")
#rootdir = 'test'
#root_to_subtract = re.compile(r'^.*?' + rootdir + r'[\\/]{0,1}')
def targetlist(folderarray):
	#takes list of folders and returns a dictionary, so you can call folders by name instead of full path
	targets={}
	for i in folderarray:
		if os.path.isdir(i):
			targets.update({i.split("/")[-1]:i})
	return targets

targets = targetlist(apk1.folders)
def targetsmali(dir):
	#gets a folder from targets and puts focus on the smali folder for blackbox class scans
	word = dir
	dir = targets[dir]
	for i in os.listdir(dir):
		q = i.split('/',1)[0].rsplit('.',1)[-1]
		if q == word:
			return dir+'/'+i+'/smali'
	#print targets['email']+'/'+i
	#print targets['email'].split('/',1)[0]

agent = targetsmali('androidagent')
email = targetsmali('email')


test = comparedir(agent,email)



in1 = 2390840
str1 = str(in1)
