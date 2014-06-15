import logging, logging.handlers
import traceback

import os
import time
import uuid
import md5
import base64
import socket
import fcntl
import struct

from threading import Thread
from threading import Event
from Queue import Queue
import email
import json
from xml.dom import minidom

import pickle
import subprocess

from Adafruit_Thermal import *

# http://sourceforge.net/p/raspberry-gpio-python/wiki/Home/
import RPi.GPIO as GPIO

import requests
from Crypto.Cipher import Blowfish
import imaplib2

CLOUDPRINT_AGENT='python-rapi0'
CLOUDPRINT_VERSION='0.1.3'

# printer manual http://www.adafruit.com/datasheets/A2-user%20manual.pdf
# http://www.proto-pic.co.uk/content/datasheets/thermalPrinter-CommandSet.pdf

class CPPersistentData(object):
	def __init__(self, fpath, fname, defaults={}):
		if not fpath:
			os.path.dirname(os.path.realpath(__file__))
		self._fpath=fpath
		self._fname=fname
		self._data={}
		self._updated=False
		self.load(defaults)

	def fpath(self):
		if not os.path.exists(self._fpath):
 			os.makedirs(self._fpath)
		return os.path.join(self._fpath, self._fname)

	def data(self):
		return self._data

	def importData(self, data):
		try:
			for key in data.keys():
				self.set(key, data[key])
		except:
			pass

	def importDefaultData(self, data):
		try:
			for key in data.keys():
				try:
					if not self.has(key):
						self.set(key, data[key])
				except:
					pass
		except:
			pass

	def load(self, defaults={}):
		try:
			with open(self.fpath(), 'rb') as f:
				self._data=pickle.load(f)
				self.importDefaultData(defaults)
		except:
			self._data=defaults
		return self._data

	def save(self):
		try:
			if self._updated:
				with open(self.fpath(), 'wb') as f:
					pickle.dump(self._data, f)
					self._updated=False
			return True
		except:
			pass

	def set(self, key, value):
		try:
			if self.get(key)!=value:
				self._data[key]=value
				self._updated=True
				return True
		except:
			pass

	def has(self, key):
		try:
			self._data[key]
			return True
		except:
			pass

	def get(self, key, default=None):
		try:
			return self._data[key]
		except:
			return default

	def __getitem__(self, key):
		return self.get(key)


class CPWebservice(object):
	def __init__(self, parent, logger):
		self._parent=parent
		self._logger=logger
		self._stampStart=time.time()
		self._macaddress=self.getMacAddress()
		self._ipaddress=self.getInterfaceIpAddress('eth0')
		self.logger.debug('webservice:mac=%s, ip=%s' % (self._macaddress, self._ipaddress))

	@property
	def parent(self):
		return self._parent

	@property
	def jobs(self):
	    return self.parent.jobs

	@property
	def logger(self):
		return self._logger

	def updateIpAddress(self):
		self._ipaddress=self.getInterfaceIpAddress('eth0')

	def flag(self, handler, delay, delayRepeat=0, initialValue=False):
		return CPWebserviceFlag(self, handler, delay, delayRepeat=0, initialValue=False)

	def getMacAddress(self, ifname='eth0'):
		# using uuid.getnode() can leads to a faked address (randomized)
		#return '-'.join('%02X' % ((uuid.getnode() >> 8*i) & 0xff) for i in reversed(xrange(6)))
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
		return ''.join(['%02x-' % ord(char) for char in info[18:24]])[:-1]

	def getInterfaceIpAddress(self, ifname='eth0'):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 
				0x8915,  # SIOCGIFADDR
				struct.pack('256s', ifname[:15])
				)[20:24])		
		except:
			self.logger.error('webservice:unable retrieve ip address!')

	def url(self):
		return 'http://digimat.ch/phpdev/cloudprint/cloudprint.php'

	def lid(self):
		return md5.md5(self.getMacAddress()).hexdigest()

	def runtime(self):
		return int(time.time()-self._stampStart)

	def uuid(self):
		return str(uuid.uuid4()).lower()

	def uncrypt(self, data, key):
		try:
			bf=Blowfish.BlowfishCipher(key)
			return bf.decrypt(base64.b64decode(data)).rstrip('\0')
		except:
			pass

	def do(self, request, payload={}):
		try:
			self.updateIpAddress()
			key=self.uuid()
			payload['command']=request.lower()
			payload['lid']=self._macaddress
			payload['lip']=self._ipaddress
			payload['agent']=CLOUDPRINT_AGENT
			payload['version']=CLOUDPRINT_VERSION
			payload['session']=key
			payload['uptime']=self.runtime()
			url=self.url()
			self.logger.debug('webservice:request[%s]' % str(payload))
			r=requests.get(url, params=payload, timeout=10)
			if r.status_code==200:
				data=self.uncrypt(r.text, key).strip()
				if data:
					data=data.strip()
					ctype=r.headers['content-type']
					self.logger.debug('webservice:response[%s:%s]' % (ctype, data))
					try:
						if 'json' in ctype:
							return json.loads(data)
						elif 'xml' in ctype:
							# try to retrieve root node
							#print "XML(%s)" % data
							#print "HEX(%s)" % ":".join("{:02x}".format(ord(c)) for c in data)
							return minidom.parseString(data).documentElement
					except:
						#traceback.print_exc()
						self.logger.warning('webservice:unable to process %s response!' % ctype)
		except:
			pass


	def handle(self, handler, payload={}):
		try:
			return self.do(handler, payload)
		except:
			self.logger.error('webservice:handle(%s) exception occured!' % handler)

	def handleAndProcessJobResponse(self, handler, payload={}):
		job=self.handle(handler, payload)
		if job:
			self.parent.submitXmlJob(job)
			return True

	def getFactorySettings(self):
		return self.handle('getfactorysettings')

	def buttonTap(self):
		if not self.handleAndProcessJobResponse('buttontap'):
			try:
				job="<root><ticket><center>MAC:%s<feed/>IP:%s<feed/></center></ticket></root>" % (self._macaddress, self._ipaddress)
				self.parent.submitXmlJobFromString(job)
			except:
				self.logger.error('webservice:buttonTap exception occured!')

	def buttonHold(self):
		return self.handleAndProcessJobResponse('buttonhold')

	def pong(self):
		return self.handleAndProcessJobResponse('pong')


class CPWebserviceFlag(object):
	def __init__(self, webservice, handler, delay, delayRepeat=0, initialValue=False):
		self._webservice=webservice
		self._handler=handler
		self._delay=delay
		self._delayRepeat=delayRepeat
		self._input=bool(initialValue)
		self._output=self._input
		self._stamp=0
		self._trigger=False
		self._stampTrigger=0
		self._timer=0

	@property
	def webservice(self):
		return self._webservice

	def observe(self, value):
		value=bool(value)
		if value!=self._input:
			self._stamp=time.time()
			self._input=value
			self._trigger=False
		self.manager()
		return self._input

	def trigger(self, repeat=False):
		try:
			repeat=int(repeat)
			payload={'value':self._output, 'repeat':repeat}
			job=self._webservice.handle(self._handler, payload)
			if job:
				self.webservice.parent.submitXmlJob(job)
			self._trigger=True
			self._stampTrigger=time.time()			
		except:
			pass

	def manager(self):
		if self._input!=self._output:
			if not self._trigger:
				if time.time()-self._stamp>=self._delay:
					self._output=self._input
					self.webservice.logger.warning('info:%s:%d' % (self._handler, self._output))
					self.trigger()
		else:
			if self._output and self._delayRepeat>0:
				if time.time()-self._stampTrigger>=self._delayRepeat:
					self.trigger(True)

	@property
	def output(self):
		return bool(self._output)

	# allow things like "if flag:"
	def __nonzero__(self):
		return self.output

	@property
	def input(self):
		return bool(self._input)

	def isTimeout(self, timeout):
		if time.time()-self._timer>=timeout:
			self._timer=time.time()
			return True


class CPThread(Thread):
	def __init__(self, parent):
		super(CPThread, self).__init__()
		self.name='CPThread'
		#self.daemon=True
		self._parent=parent
		self._eventStart=Event()
		self._eventStop=Event()
		self._onInit()

	@property
	def logger(self):
		return self.parent.logger

	@property
	def parent(self):
		return self._parent

	def sleep(self, delay):
		return self._eventStop.wait(delay)

	def start(self):
		super(CPThread, self).start()
		self._onStart()

	def run(self):
		self._eventStart.set()
		while not self.isStopRequest():
			self._onRun()

	def stop(self):
		if not self.isStopRequest():
			self._eventStop.set()
			self._onStop()

	def release(self):
		self._onRelease()

	def waitUntilStarted(self):
		self._eventStart.wait()

	def isStopRequest(self):
		return self._eventStop.isSet()

	def _onInit(self):
		return self.onInit()

	def onInit(self):
		pass

	def _onRelease(self):
		return self.onRelease()

	def onRelease(self):
		pass

	def _onStart(self):
		return self.onStart()

	def onStart(self):
		pass

	def _onRun(self):
		return self.onRun()

	def onRun(self):
		time.sleep(0.1)

	def _onStop(self):
		return self.onStop()

	def onStop(self):
		pass


class CPPrinterStateStack(object):
	def __init__(self, default=None):
		self._stack=None
		self._default=default
		self.reset()

	def reset(self):
		self._stack=[]

	def push(self, state):
		self._stack.append(state)

	def pop(self):
		try:
			return self._stack.pop()
		except:
			return self._default

	def current(self):
		try:
			return self._statck[-1]
		except:
			return self._default


class CPPrinterState(object):
	def __init__(self):
		self._states={}
		self.register('size', 'small')
		self.register('align', 'left')
		self.register('bold', False)
		self.register('underline', False)
		self.register('inverse', False)

	def reset(self):
		for state in self._states.values():
			state.reset()

	def register(self, name, default):
		self._states[name]=CPPrinterStateStack(default)

	@property
	def size(self):
		return self._states['size']

	@property
	def align(self):
		return self._states['align']

	@property
	def bold(self):
		return self._states['bold']

	@property
	def underline(self):
		return self._states['underline']

	@property
	def inverse(self):
		return self._states['inverse']


class CPPrinter(object):
	def __init__(self, logger):
		self._logger=logger
		self._states=CPPrinterState()
		self._printer=None

	@property
	def logger(self):
		return self._logger

	@property
	def printer(self):
		self.open()
		return self._printer	

	def open(self):
		try:
			if not self._printer:
				self.logger.info('printer:opening device...')
				self._printer=Adafruit_Thermal('/dev/ttyAMA0', 19200, timeout=5)
				self.printer.wake()
				self.printer.reset()
				self.printer.setDefault()
			return True
		except:
			self.logger.error('printer:open() error')

	def close(self):
		del self._printer
		self._printer=None
		self.logger.info('printer:device closed')

	def hasPaper(self):
		#self.logger.debug('printer:hasPaper()')
		retry=2
		while retry:
			try:
				if self.printer.hasPaper():
					return True
			except:
				self.logger.error('printer:hasPaper() error')
				self.close()
			retry-=1

	def reset(self, setDefault=False):
		self.logger.debug('printer:reset()')
		try:
			self._states.reset()
			self.printer.wake()
			self.printer.reset()
			#has a drawback, since it send a line feed (in setSize)
			if setDefault:
				self.printer.setDefault()
		except:
			self.logger.error('printer:reset() error')
			self.close()

	def online(self, state=True):
		self.logger.debug('printer:online(%d)' % state)
		try:
			if state:
				self.printer.online()
			else:
				self.printer.offline()
		except:
			self.logger.error('printer:online() error')
			self.close()

	def bold(self, state=True, store=True):
		try:
			state=bool(state)
			self.logger.debug('printer:bold(%d)' % state)
			if store:
				self._states.bold.push(state)
			if state:
				self.printer.boldOn()
			else:
				self.printer.boldOff()
		except:
			self.logger.error('printer:bold() error')
			self.close()

	def restoreBold(self):
		cstate=self._states.bold.pop()
		lstate=self._states.bold.current()
		if lstate!=cstate:
			self.bold(lstate, False)

	def underline(self, state=True, store=True):
		try:
			state=bool(state)
			self.logger.debug('printer:underline(%d)' % state)
			if store:
				self._states.underline.push(state)
			if state:
				self.printer.underlineOn(1)
			else:
				self.printer.underlineOff()
		except:
			self.logger.error('printer:underline() error')
			self.close()

	def restoreUnderline(self):
		cstate=self._states.underline.pop()
		lstate=self._states.underline.current()
		if lstate!=cstate:
			self.underline(lstate, False)

	def inverse(self, state=True, store=True):
		try:
			state=bool(state)
			self.logger.debug('printer:inverse(%d)' % state)
			if store:
				self._states.inverse.push(state)
			if state:
				self.printer.inverseOn()
			else:
				self.printer.inverseOff()
		except:
			self.logger.error('printer:inverse() error')
			self.close()

	def restoreInverse(self):
		cstate=self._states.inverse.pop()
		lstate=self._states.inverse.current()
		if lstate!=cstate:
			self.inverse(lstate, False)

	def size(self, size, store=True):
		try:
			size=size.lower()
			if not size in ['small', 'medium', 'large']:
				size='small'
			self.logger.debug('printer:size(%s)' % size)
			if store:
				self._states.size.push(size)

			if size=='large':
				self.printer.setSize('M')
			elif size=='medium':
				self.printer.setSize('M')
			else:
				self.printer.setSize('S')
		except:
			self.logger.error('printer:size() error')
			self.close()

	def restoreSize(self):
		csize=self._states.size.pop()
		lsize=self._states.size.current()
		if lsize!=csize:
			self.size(lsize, False)

	def align(self, mode, store=True):
		try:
			mode=mode.lower()
			if not mode in ['left', 'center', 'right']:
				mode='left'
			if store:
				self._states.align.push(mode)
			if mode=='right':
				self.printer.justify('R')
			elif mode=='center':
				self.printer.justify('C')
			else:
				self.printer.justify('L')
		except:
			self.logger.error('printer:align() error')
			self.close()

	def restoreAlign(self):
		cmode=self._states.align.pop()
		lmode=self._states.align.current()
		if lmode!=cmode:
			self.align(lmode, False)

	def feed(self, lines=1):
		self.logger.debug('printer:feed()')
		try:
			self.printer.feed(lines)
		except:
			self.logger.error('printer:feed() error')
			self.close()

	def write(self, data, trace=True):
		if data:
			if trace:
				self.logger.debug('printer:write(%s)' % data)
			try:
				self.printer.write(data)
			except:
				self.logger.error('printer:write() error')
				self.close()



class CPJobs(CPThread):
	def onInit(self):
		self._jobs=Queue()
		self._printer=CPPrinter(self.logger)
		self._flagOutOfPaper=self.parent.webservice.flag('outofpaper', 2, 3600*24)

	@property
	def printer(self):
	    return self._printer

	def submitXmlJob(self, job):
		try:
			if job:
				self.logger.debug('jobs:sumbit')
				self._jobs.put(job)
				return True
		except:
			pass

	def submitXmlJobFromString(self, strjob):
		try:
			job=minidom.parseString(strjob).documentElement
			if job:
				return self.submitXmlJob(job)
		except:
			pass

	def pop(self):
		try:
			return self._jobs.get(False)
		except:
			pass

	def isQueueEmpty(self):
		return self._jobs.empty()

	def isPrinterReady(self):
		return self.isQueueEmpty() and not self._flagOutOfPaper

	def reboot(self):
		subprocess.call("sync")
		subprocess.call(["reboot"])

	def parseCommand(self, node):
		while node:
			try:
				if node.nodeType==minidom.Node.ELEMENT_NODE:
					name=node.nodeName.lower()
					self.logger.debug('command:%s' % name)
					if name=='reboot':
						self.reboot()
					elif name=='restart':
						self.parent.stop()
					elif name=='ping':
						self.parent.webservice.pong()
				node=node.nextSibling
			except:
				self.logger.error('command:exception occured!')
				break

	def parseTicket(self, node):
		while node:
			try:
				if node.nodeType==minidom.Node.TEXT_NODE:
					data=node.data.strip()
					if data:
						data=data.replace('$', ' ')
						self.printer.write(data)
				elif node.nodeType==minidom.Node.ELEMENT_NODE:
					name=node.nodeName.lower()
					child=node.firstChild
					if name=='br':
						self.printer.write('\n', False)
					elif name=='space':
						self.printer.write(' ', False)
					elif name=='bold':
						self.printer.bold()
						self.parseTicket(child)
						self.printer.restoreBold()
					elif name=='underline':
						self.printer.underline()
						self.parseTicket(child)
						self.printer.restoreUnderline()
					elif name=='inverse':
						self.printer.inverse()
						self.parseTicket(child)
						self.printer.restoreInverse()
					elif name=='feed':
						self.printer.feed()
					elif name in ['small', 'medium', 'large']:
						self.printer.size(name)
						self.parseTicket(child)
						self.printer.restoreSize()
					elif name in ['left', 'center', 'right']:
						self.printer.align(name)
						self.parseTicket(child)
						self.printer.restoreAlign()
					else:
						self.logger.warning('ticket:ignoring unsupported tag [%s]' % name)
						self.parseTicket(child)
				node=node.nextSibling
			except:
				self.logger.error('ticket:exception occured!')
				break

	def parseMessage(self, root):
		try:
			self.logger.debug('jobs:parsing xml message...')
			for item in root.childNodes:
				name=item.nodeName.lower()
				if name=='ticket':
					alarm=False
					critical=False
					ack=False
					try:
						alarm=bool(item.attributes['alarm'])
					except:
						pass
					try:
						critical=bool(item.attributes['critical'])
					except:
						pass
					try:
						ack=bool(item.attributes['ack'])
					except:
						pass
					if alarm:
						self.parent.beep(3)
						if critical:
							self.parent.permanentBuzzer(1)
					if ack:
						self.parent.permanentBuzzer(0)
						
					self.printer.reset()
					self.parseTicket(item.firstChild)
					self.printer.feed(3)
				elif name=='command':
					self.parseCommand(item.firstChild)
		except:
			self.logger.error('jobs:unable to parse xml')
		return True

	def onStart(self):
		pass

	def onRun(self):
		if self._flagOutOfPaper.isTimeout(2):
			if self._flagOutOfPaper.observe(not self.printer.hasPaper()):
				self.parent.beep()

		if not self._flagOutOfPaper.input:
			data=self.pop()
			if data:
				self.parseMessage(data)
		self.sleep(0.5)

	def onStop(self):
		pass

	def onRelease(self):
		pass


class CPMailBox(CPThread):
	def setImapServer(self, server, user, password, fetchDelay=15):
		self._server=server
		self._user=user
		self._password=password
		self._imap=None
		self._mdata=None
		self._mid=None
		self._messages=[]
		self._fetchDelay=fetchDelay
		self._fetchTimeout=0
		self._prune=False

	def disconnect(self):
		if self._imap:
			try:
				self._imap.logout()
				del self._imap
				self.logger.info('imap:disconnected')
				self.parent.led(0)
			except:
				pass
		self._imap=None

	def prune(self):
		self.logger.warning('mailbox:pruning requested!')
		self._prune=True

	def noop(self):
		try:
			if self._imap:
				self.parent.led(0)
				result, messages=self._imap.noop()
				if result=='OK':
					self.parent.led(1)
					return True
		except:
			self.logger.warning('imap:noop failed, link broken!')

	def ascii(self, s):
		try:
			return s.encode('ascii', 'ignore')
		except:
			return s 

	def connect(self):
		if self.noop():
			return True
		self.disconnect()
		try:
			self.logger.info('imap:connecting to server %s...' % self._server)
			self._imap=imaplib2.IMAP4_SSL(host=self.ascii(self._server), timeout=30, debug=0)
			result=self._imap.login(self.ascii(self._user), self.ascii(self._password))
			if result[0]=='OK':
				self._imap.select(mailbox='INBOX')
				self.logger.info('imap:connected!')
				self.parent.led(1)
				return True
		except:
			self.logger.error('imap:unable to connect!')

	def fetchMessage(self):
		self._mid=None
		self._mdata=None
		if self.connect():
			try:
				# search criterias described here 
				# http://www.php.net/manual/en/function.imap-search.php
				result, mids = self._imap.search(None, 'UNDELETED')
				if result=='OK':
					mids=mids[0].split()
					self.logger.debug('imap:%d messages pending on server' % len(mids))
					if mids:
						mid=mids[0]
						result, mdata = self._imap.fetch(mid, '(RFC822)')
						if result=='OK':
							self._mdata=mdata[0][1]
							self._mid=mid
							self.logger.debug('imap:message id %s retrieved' % self._mid)
							return self._mdata
			except:
				self.logger.error('imap:error occured while fetching message!')
				self.disconnect()
		else:
			self.parent.beep(2)


	def deleteMessage(self):
		if self._mid:
			if self.connect():
				try:
					self._imap.store(self._mid, '+FLAGS', '\\Deleted')
					self._imap.expunge()
					self.logger.info('imap:message %s successfully deleted' % self._mid)
				except:
					self.logger.error('imap:error occured while deleting message %s!' % self._mid)
					self.disconnect()

	def onStart(self):
		pass

	def onRun(self):
		if self._prune:
			self._prune=False
			self.logger.info('mailbox:pruning...')
			self.parent.beep(5)
			while not self.isStopRequest():
				msg=self.fetchMessage()
				if not msg:
					break
				self.deleteMessage()
				self.logger.warning('mailbox:prunning message!')
			self.logger.info('mailbox:prunning done.')

		if not self.parent.isPrinterReady():
			self.sleep(1)
		else:
			if time.time()>=self._fetchTimeout:
				msg=self.fetchMessage()
				if not msg:
					self._fetchTimeout=time.time()+15
				else:
					try:
						m=email.message_from_string(msg)
						if m:
							self.logger.debug('mailbox:processing message %s' % m['Message-ID'])
							for part in m.walk():
								self.logger.debug('mailbox:found message part [%s]' % part.get_content_type())
								# each part is a either non-multipart, or another multipart message
								# that contains further parts... Message is organized like a tree
								if part.get_content_type()=='text/plain':
									try:
										#print part.get_payload()
										job=minidom.parseString(part.get_payload().strip()).documentElement
										self.parent.submitXmlJob(job)
									except:
										pass
					except:
						self.logger.error('mailbox:error while decoding RFC822 message!')
					finally:
						self.deleteMessage()
		self.sleep(0.5)

	def onStop(self):
		pass

	def onRelease(self):
		self.disconnect()


class CloudPrint(object):
	def __init__(self, logServer='localhost', logLevel=logging.DEBUG):
		logger=logging.getLogger('CLOUDPRINT')

		logger.setLevel(logLevel)
		socketHandler = logging.handlers.SocketHandler(logServer, logging.handlers.DEFAULT_TCP_LOGGING_PORT)
		logger.addHandler(socketHandler)
		self._logger=logger

		self._eventStop=Event()

		self._webservice=CPWebservice(self, self.logger)
		self._flagWatchdog=CPWebserviceFlag(self.webservice, 'watchdog', 60, 900)

		self._persistentData=CPPersistentData('/etc/cloudprint', 'cloudprint.pdata')
		factorySettings=self._webservice.getFactorySettings()
		if factorySettings:
			self._persistentData.importData(factorySettings)
			self._persistentData.save()

		self.gpioInit()

		self._jobs=CPJobs(self)
		self._mailbox=CPMailBox(self)
		self._mailbox.setImapServer(self.persistentData['imap'], 
			self.persistentData['user'], 
			self.persistentData['password'])

	@property
	def logger(self):
		return self._logger

	@property
	def webservice(self):
		return self._webservice

	@property
	def jobs(self):
		return self._jobs

	@property
	def mailbox(self):
		return self._mailbox

	@property
	def persistentData(self):
		return self._persistentData

	def gpioInit(self):
		try:
			self._lastButtonState=0
			self._lastButtonTime=time.time()
			self._buttonHoldEnable=False
			self._buttonTapEnable=False
			self._gpioLedPin=18
			self._gpioButtonPin=23
			self._gpioBuzzerPin=22
			self._permanentBuzzer=False
			self._stampBuzzer=0
			self._stateBuzzer=0
			GPIO.setmode(GPIO.BCM)
			GPIO.setwarnings(False)
			GPIO.setup(self._gpioLedPin, GPIO.OUT)
			GPIO.setup(self._gpioBuzzerPin, GPIO.OUT)
			GPIO.setup(self._gpioButtonPin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

			self.led(0)
			self.buzzer(0)
		except:
			pass

	def gpioRelease(self):
		GPIO.cleanup()

	def led(self, state):
		try:
			if state:
				GPIO.output(self._gpioLedPin, GPIO.HIGH)
			else:
				GPIO.output(self._gpioLedPin, GPIO.LOW)
		except:
			self.logger.warning('led: unable to access gpio LED')

	def buzzer(self, state):
		try:
			state=bool(state)
			if state:
				GPIO.output(self._gpioBuzzerPin, GPIO.HIGH)
			else:
				GPIO.output(self._gpioBuzzerPin, GPIO.LOW)

			if state != self._stateBuzzer:
				self._stateBuzzer=state
				self._stampBuzzer=time.time()
		except:
			self.logger.warning('led: unable to access gpio BUZZER')

	def permanentBuzzer(self, state):
		self._permanentBuzzer=bool(state)
		self.buzzer(state)

	def beep(self, n=1, delay=0.07):
		for b in range(n):
			self.buzzer(1)
			self.sleep(delay)
			self.buzzer(0)
			self.sleep(delay)

	def button(self):
		try:
			return GPIO.input(self._gpioButtonPin)
		except:
			pass

	def submitXmlJob(self, job):
		try:
			self._jobs.submitXmlJob(job)
		except:
			pass

	def submitXmlJobFromString(self, job):
		try:
			self._jobs.submitXmlJobFromString(job)
		except:
			pass

	def isPrinterReady(self):
		return self._jobs.isPrinterReady()

	def start(self):
		self.logger.info('starting service...')
		self._jobs.start()
		self._jobs.waitUntilStarted()
		self._mailbox.start()
		self._mailbox.waitUntilStarted()

		try:
			while not self._eventStop.wait(0.02):
				self.manager()
		except KeyboardInterrupt:
			msg="service halted by keyboard..."
			print msg
			self.logger.info(msg)
			self.stop()
		except:
			self.logger.info("service halted by unhandled exception...")
			self.stop()
		finally:
			self.logger.info("waiting for service threads termination...")
			self._jobs.join()
			self._mailbox.join()
			self.logger.info("service threads halted.")

			self.logger.info('releasing service threads...')
			self._jobs.release()
			self._mailbox.release()

			self.gpioRelease()

			self.logger.info("service halted.")

	def buttonManager(self):
		buttonState = self.button()
		t=time.time()

		if buttonState!=self._lastButtonState:
			self._lastButtonState=buttonState
			self._lastButtonTime=t
		else:
			if (t-self._lastButtonTime) >= 2.0:
				if self._buttonHoldEnable:
					self.logger.debug('button:onHold()')
					self.webservice.buttonHold();
					self._mailbox.prune()
					self._buttonHoldEnable=False
					self._buttonTapEnable=False
			elif (t-self._lastButtonTime)>=0.1:
				if buttonState:
					if self._buttonTapEnable:
						self.logger.debug('button:onTap()')
						self.permanentBuzzer(0)
						self.beep()
						self.webservice.buttonTap();
						self._buttonTapEnable=False
						self._buttonHoldEnable=False
				else:
					self._buttonTapEnable=True
					self._buttonHoldEnable=True

	def manager(self):
		self.buttonManager()
		self._flagWatchdog.observe(1)
		if self._permanentBuzzer:
			t=time.time()-self._stampBuzzer
			if self._stateBuzzer and t>=0.3:
				self.buzzer(0)
			elif not self._stateBuzzer and t>=1.0:
				self.buzzer(1)
		self.sleep(0.01)

	def sleep(self, delay):
		self._eventStop.wait(delay)

	def stop(self):
		if not self._eventStop.isSet():	
			self._eventStop.set()

		self.logger.info('halting service threads...')
		self._jobs.stop()
		self._mailbox.stop()

cp=CloudPrint('192.168.0.84')
cp.start()
