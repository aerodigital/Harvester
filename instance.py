from subprocess import Popen,PIPE,call
from drozer import console
import argparse, textwrap, os, getpass, sys, warnings, shlex


from pydiesel.api.protobuf_pb2 import Message
from drozer.console.session import Session, DebugSession
from drozer.connector import ServerConnector
#makes a instance spawner

tempdir = os.path.expanduser('~/temp1')
drozerinstall = 'https://www.mwrinfosecurity.com/system/assets/613/original/drozer-2.3.3.tar.gz'
os.chdir(tempdir)
print os.getcwd()

def __init__(self):
	if os.path.isfile('/usr/bin/drozer'):
		print 'drozer works...main'
	else:
		print "Drozer is not installed"


class Console(console.Console):
	def __init__(self, add_help=True):
		#doc_text = textwrap.dedent(self.__doc__).strip().split("\n")
		#not resolving, fix later
		doc_text = ['']
		self._parser = argparse.ArgumentParser(add_help=add_help, description="\n".join(doc_text[1:]), usage=doc_text[0])
		self._parser.add_argument("command", default=None, help="the command to execute")
		self._parser.add_argument("device", default=None, nargs='?', help="the unique identifier of the Agent to connect to")
		self._parser.add_argument("--server", default=None, metavar="HOST[:PORT]", help="specify the address and port of the drozer server")
		self._parser.add_argument("--ssl", action="store_true", default=False, help="connect with SSL")
		self._parser.add_argument("--accept-certificate", action="store_true", default=False, help="accept any SSL certificate with a valid trust chain")
		self._parser.add_argument("--debug", action="store_true", default=False, help="enable debug mode")
		self._parser.add_argument("--no-color", action="store_true", default=False, help="disable syntax highlighting in drozer output")
		self._parser.add_argument("--password", action="store_true", default=False, help="the agent requires a password")
		self._parser.add_argument("-c", "--command", default=None, dest="onecmd", help="specify a single command to run in the session")
		self._parser.add_argument("-f", "--file", default=[], help="source file", nargs="*")

		self.__accept_certificate = False
		self.__server = None
		self.__privtext = 'test private'
		self.idlist = []
	def do_connect(self, arguments):
		"""starts a new session with a device"""
		if arguments.password:
			with warnings.catch_warnings():
				warnings.simplefilter("ignore")

				password = getpass.getpass()
		else:
			password = None
			print "No auth"
		device = self.__get_device(arguments)
		server = self.__getServerConnector(arguments)
		print 'Checking response'
		if self.idlist:
			for i in self.idlist:
				i = i[0]
				#print i
				response = server.startSession(i, password)
		print response, "=-=-=-=-=-=-=-=-"
		print response, 'Connection Complete\n------------------------------------------------------------\n'

		if response.type == Message.SYSTEM_RESPONSE and\
			response.system_response.status == Message.SystemResponse.SUCCESS:
			session_id = response.system_response.session_id

			try:
				#hard coding debug mode
				#session = DebugSession(server, session_id, arguments)
				if(arguments.debug):
						pass#session = DebugSession(server, session_id, arguments)
				else:
					session = Session(server, session_id, arguments)
				'''
				if len(arguments.file) > 0:
						session.do_load(" ".join(arguments.file))
						session.do_exit("")
				elif arguments.onecmd != None:
						session.onecmd(arguments.onecmd)
						session.do_exit("")
				else:
						session.cmdloop()
				'''
			except KeyboardInterrupt:
				print
				print "Caught SIGINT, terminating your session."
			#finally:
				#session.do_exit("")

				#self.__getServerConnector(arguments).close()
		else:
				self.handle_error(RuntimeError(response.system_response.error_message), fatal=True)
		return session
	def __get_device(self, arguments):
		"""
		Determines which device to request after connecting to the server.
		"""
		if self.arguments.device == None:
			devices = self.__getServerConnector(arguments).listDevices().system_response.devices
			print devices, "Devices: "

			if len(devices) == 1:
				device = devices[0].id

				print "Selecting %s (%s %s %s)\n" % (devices[0].id, devices[0].manufacturer, devices[0].model, devices[0].software)

				return device
			elif len(devices) == 0:
				print "No devices available.\n"

				sys.exit(-1)
			else:
				print "More than one device available. Please specify the target device ID.\n"
				for i in devices:
					self.idlist.append(i)

		else:
			return arguments.device

	def __getServerConnector(self, arguments):
		"""
		Get a Server object which provides a connection to the selected server.
		"""
		if self.__server == None:
			print 'getting server'
			try:
				self.__server = ServerConnector(arguments, self.__manage_trust)
			except ServerConnector as e:
				print e
		return self.__server

	def __manage_trust(self, provider, certificate, peer):
		"""
		Callback, invoked when connecting to a server with SSL, to manage the trust
		relationship with that server based on SSL certificates.
		"""
		trust_status = provider.trusted(certificate, peer)

		if trust_status < 0:
			if self.__accept_certificate:
					"""
					If the --accept-certificate option indicates we should blindly accept
					this certificate, carry on.
					"""
					return

			print "drozer has established an SSL Connection to %s:%d." % peer
			print "The server has provided an SSL Certificate with the SHA-1 Fingerprint:"
			print "%s\n" % provider.digest(certificate)

			if trust_status == -2:
				print "WARNING: this host has previously used a certificate with the fingerprint:"
				print "%s\n" % provider.trusted_certificate_for(peer)

			while(True):
				#print "Do you want to accept this certificate? [yna] ",
				print 'Auto accepting certificate'
				selection = 'a'

				if selection == "n":
					sys.exit(-2)
				elif selection == "y":
					print 'what?'
					break
				elif selection == "a":
					print "Adding certificate to known hosts.\n"
					provider.trust(certificate, peer)
					break
	def send(self, list=[]):
		for command in list:
			command = session.precmd(command)
			stop = session.onecmd(command)
			print stop, "STOP"
			stop = session.postcmd(stop, command)

#instance the console class
dz = Console()

#this is the original args
argv = ['connect','--server','198.23.229.57:31415', '--ssl']
#later we will get devices and put them below
devs = []

#these do some magic on the class vars so the other methods have the data they need
dz.prepare_argument_parser(argv)
dz.arguments = dz.parse_arguments(dz._parser, argv)
#attempt to connect, must instance so it maintains state?
dz.do_connect(dz.arguments)


#iterate through a list of commands
#TODO: Control output with a method so these commands get written to the log
stuff = ['list']
for i in dz.idlist:
	devs.append(str(i.id))
print devs
#test = dz.boom.stdout



#10.35.129.77
#10.33.146.43

'''
session.stdin = 'list'
session.use_rawinput = False
log = '/home/job/temp1/test.txt'
print shlex.split(logs, comments=True)
dz.send(['list'])
#dz.getServerConnector(argv)


'''
'''
try:
	dz.do_connect(dz.arguments)

except Exception, e:
	print 'Error: ', e

'''



#for i in dir(dz):
#	print i
#hey = dz.run(['connect','--server','10.35.129.77:31415'])
#print hey