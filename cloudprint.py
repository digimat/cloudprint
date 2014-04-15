import time
from threading import Thread
from threading import Event
import logging, logging.handlers
import imaplib2
import email
import traceback
from xml.dom import minidom
from Adafruit_Thermal import *
import RPi.GPIO as GPIO
import os
import pickle
import uuid
import md5
import base64
import requests
import json
import subprocess
from Crypto.Cipher import Blowfish

# printer manual http://www.adafruit.com/datasheets/A2-user%20manual.pdf

class CPPersistentData(object):
	def __init__(self, fname, defaults={}):
		self._fname=fname
		self._data={}
		self._updated=False
		self.load(defaults)

	def fpath(self):
		return os.path.join(os.path.dirname(os.path.realpath(__file__)), self._fname)

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
	def __init__(self, logger):
		self._logger=logger
		self._macaddress=self.macaddr()

	@property
	def logger(self):
	    return self._logger

	def macaddr(self):
		return '-'.join('%02X' % ((uuid.getnode() >> 8*i) & 0xff) for i in reversed(xrange(6)))

	def url(self):
		return 'http://digimat.ch/phpdev/cloudprint/cloudprint.php'

	def lid(self):
		return md5.md5(self.macaddr()).hexdigest()

	def uuid(self):
		return str(uuid.uuid4()).lower()

	def processResponse(self, data, key):
		try:
			#bf=blowfish.Blowfish(key)
			#response=bf.decryptstr(base64.b64decode(data))
			bf=Blowfish.BlowfishCipher(key)
			response=bf.decrypt(base64.b64decode(data))
			return json.loads(response)
		except:
			pass

	def do(self, request, payload={}):
		try:
			key=self.uuid()
			payload['command']=request.lower()
			payload['lid']=self.macaddr()
			payload['session']=key
			url=self.url()
			self.logger.debug('webservice:request%s]' % str(payload))
			r=requests.get(url, params=payload, timeout=10)
			if r.status_code==200:
				return self.processResponse(r.text, key)
		except:
			pass

		self.logger.error('webservice:request error!')

	def getFactorySettings(self):
		return self.do('getfactorysettings')

	def buttonTap(self):
		return self.do('buttontap')

	def buttonHold(self):
		return self.do('buttonhold')


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
	def __init__(self, parent):
		self._parent=parent
		self._states=CPPrinterState()
		self._printer=None

	@property
	def logger(self):
		return self.parent.logger

	@property
	def parent(self):
		return self._parent

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
		self.logger.debug('printer:hasPaper()')
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
				self.logger.warning('right')
			elif mode=='center':
				self.printer.justify('C')
				self.logger.warning('center')
			else:
				self.printer.justify('L')
				self.logger.warning('left')
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


class CPMailBox(CPThread):
	def setImapServer(self, server, user, password):
		self._server=server
		self._user=user
		self._password=password
		self._imap=None
		self._mdata=None
		self._mid=None
		self._printer=CPPrinter(self)

	@property
	def printer(self):
	    return self._printer

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
						self.printer.write(data)
				elif node.nodeType==minidom.Node.ELEMENT_NODE:
					name=node.nodeName.lower()
					child=node.firstChild
					if name=='br':
						self.printer.write('\n', False)
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

	def parseMessage(self, data):
		try:
			doc = minidom.parseString(data)
			root = doc.documentElement
			for item in root.childNodes:
				name=item.nodeName.lower()
				if name=='ticket':
					self.printer.reset()
					self.parseTicket(item.firstChild)
					self.printer.feed(3)
				elif name=='command':
					self.parseCommand(item.firstChild)
		except:
			self.logger.error('mailbox:unable to parse xml')
		return True

	def onRun(self):
		while not self.isStopRequest():
			if not self.printer.hasPaper():
				self.logger.warning('printer:paper tray empty!')
				self.sleep(10)
				continue

			msg=self.fetchMessage()
			if not msg:
				self.sleep(15)
				break
			try:
				m=email.message_from_string(msg)
				if m:
					self.logger.debug('mailbox:processing message %s' % m['Message-ID'])
					for part in m.walk():
						self.logger.debug('mailbox:found message part [%s]' % part.get_content_type())
						# each part is a either non-multipart, or another multipart message
						# that contains further parts... Message is organized like a tree
						if part.get_content_type()=='text/plain':
							#print part.get_payload()
							self.parseMessage(part.get_payload().strip())
			except:
				self.logger.error('mailbox:error while decoding RFC822 message!')
			finally:
				self.deleteMessage()

	def onStop(self):
		self.disconnect()

	def onRelease(self):
		pass


class CloudPrint(object):
	def __init__(self, logServer='localhost', logLevel=logging.DEBUG):
		logger=logging.getLogger('CLOUDPRINT')

		logger.setLevel(logLevel)
		socketHandler = logging.handlers.SocketHandler(logServer, logging.handlers.DEFAULT_TCP_LOGGING_PORT)
		logger.addHandler(socketHandler)
		self._logger=logger

		self._webservice=CPWebservice(self.logger)

		self._persistentData=CPPersistentData('cloudprint.pdata')
		factorySettings=self._webservice.getFactorySettings()
		if factorySettings:
			self._persistentData.importData(factorySettings)
			self._persistentData.save()

		self._eventStop=Event()

		self.gpioInit()

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
			GPIO.setmode(GPIO.BCM)
			GPIO.setwarnings(False)
			GPIO.setup(self._gpioLedPin, GPIO.OUT)
			GPIO.setup(self._gpioButtonPin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
			self.led(0)
		except:
			pass

	def led(self, state):
		try:
			if state:
				GPIO.output(self._gpioLedPin, GPIO.HIGH)
			else:
				GPIO.output(self._gpioLedPin, GPIO.LOW)
		except:
			self.logger.warning('led: unable to access gpio LED')

	def button(self):
		try:
			return GPIO.input(self._gpioButtonPin)
		except:
			pass

	def start(self):
		self.logger.info('starting service...')
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
			self._mailbox.join()
			self.logger.info("service threads halted.")
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
					self._buttonHoldEnable=False
					self._buttonTapEnable=False
			elif (t-self._lastButtonTime)>=0.1:
				if buttonState:
					if self._buttonTapEnable:
						self.logger.debug('button:onTap()')
						self.webservice.buttonTap();
						self._buttonTapEnable=False
						self._buttonHoldEnable=False
				else:
					self._buttonTapEnable=True
					self._buttonHoldEnable=True

	def manager(self):
		self.buttonManager()
		self.sleep(0.01)

	def sleep(self, delay):
		self._eventStop.wait(delay)

	def stop(self):
		if not self._eventStop.isSet():	
			self._eventStop.set()

		self.logger.info('halting service threads...')
		self._mailbox.stop()

		self.logger.info('releasing service threads...')
		self._mailbox.release()


cp=CloudPrint('192.168.0.84')
cp.start()
