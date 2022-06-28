#coding:utf-8
import os

ZimbraPath = '/opt/zimbra/jetty/webapps/'  # /opt/zimbra/jetty/webapps/
LogFile = 'log.ini'
WebshellFeatures = (['Runtime.getRuntime().exec'], ['ClassLoader', 'defineClass'])


def find_feature(_path):
	f = open(_path)
	data = f.read()
	f.close()
	for flists in WebshellFeatures:
		for key in flists:
			if key in data:
				return True
	return False


def find_webshell():
	for root, dirs, files in os.walk(ZimbraPath):
		for file in files:
			if file.endswith('.jsp'):
				if find_feature(os.path.join(root, file)):
					with open(LogFile, 'a+') as f:
						f.write(os.path.join(root, file) + '\n')



if __name__ == '__main__':
	find_webshell()
