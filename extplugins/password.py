#
# Password Plugin for BigBrotherBot(B3) (www.bigbrotherbot.com)
# Copyright (C) 2010 Mark Weirath (xlr8or@xlr8or.com)
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA    02110-1301    USA
#
# Changelog:
# 27-10-2012 : xlr8or
# * Fixed error in nicepass and added 'from address' to the config.

__version__ = '1.0.1'
__author__  = 'xlr8or'

import b3, smtplib, string, re, sys
import b3.events
import b3.plugin
from distutils import version
from email.mime.text import MIMEText
from b3.querybuilder import QueryBuilder

#--------------------------------------------------------------------------------------------------
class PasswordPlugin(b3.plugin.Plugin):
    _adminPlugin = None
    sendMail = True
    _fromAddress = ''
    _host = 'localhost'
    _subject = 'B3 just generated a password for you'
    _introduction = 'Please log in with the following credentials:'
    _tail = 'This is an automagically generated email, do not reply to this mail.'


    def startup(self):
        """\
        Initialize plugin settings
        """

        # get the admin plugin so we can register commands
        self._adminPlugin = self.console.getPlugin('admin')
        if not self._adminPlugin:
            # something is wrong, can't start without admin plugin
            self.error('Could not find admin plugin')
            return False
        
        # register our commands
        if 'commands' in self.config.sections():
            for cmd in self.config.options('commands'):
                level = self.config.get('commands', cmd)
                sp = cmd.split('-')
                alias = None
                if len(sp) == 2:
                    cmd, alias = sp

                func = self.getCmd(cmd)
                if func:
                    self._adminPlugin.registerCommand(self, cmd, level, func, alias)

        # a shortcut makes life easier
        self.privateMsg = self.console.privateMsg
        if self.privateMsg:
            self.debug('We can send Private Messages!')

        # protect the B3 user somewhat, may the hint be understood!
        self.testAvail()

        self.debug('Started')

    def onLoadConfig(self):
        try:
            self._fromAddress = self.config.get('settings', 'from_address')
        except Exception, err:
            self.error(err)        

    def getCmd(self, cmd):
        cmd = 'cmd_%s' % cmd
        if hasattr(self, cmd):
            func = getattr(self, cmd)
            return func

        return None

    def onEvent(self, event):
        pass

    def cmd_setpass(self, data, client, cmd=None):
        """\
        <password> [<name>] - set a password for a client by hand (do it privately!)
        """
        data = string.split(data)
        if len(data) > 1:
            sclient = self._adminPlugin.findClientPrompt(data[1], client)
            if not sclient: return        
            if client.maxLevel <= sclient.maxLevel and client.maxLevel < 100:
                client.message('You can only change passwords of yourself or lower level players.')
                return
        else:
            sclient = client
        pwdhash = self.hashPassword(data[0])
        self.storePassword(sclient, pwdhash)
        return

    def cmd_generatepass(self, data, client, cmd=None):
        """\
        [<email-address>] - Generate a new password
        """
        e = self.checkEmail(data)
        pwd = self.generatePassword()
        if self.privateMsg:
            #self.debug('Password for %s: %s' %(client.name, pwd))
            client.message('Your new password is: %s' %pwd)
        if e == 'Valid':
            self.sendMail(client, pwd, data)
            self.storeEmail(client, data)
        elif e == 'None':
            pass
        else:
            client.message(e)
        pwdhash = self.hashPassword(pwd)
        self.storePassword(client, pwdhash)
        pass

    def cmd_resetpass(self, data, client, cmd=None):
        self.cmd_generatepass(data, client, cmd)
        return

    def generatePassword(self):
        return self.nicepass(6,3)
    
    # NicePass snippet by:
    # Pradeep Kishore Gowda <pradeep at btbytes.com >
    # License : GPL 
    # Date : 2005.April.15
    # Revision 1.2 
    def nicepass(self, alpha=6, numeric=2):
        """
        returns a human-readble password (say rol86din instead of 
        a difficult to remember K8Yn9muL ) 
        """
        import string
        import random
        vowels = ['a','e','i','o','u']
        consonants = [a for a in string.ascii_lowercase if a not in vowels]
        digits = string.digits
        
        ####utility functions
        def a_part(slen):
            ret = ''
            for i in range(slen):			
                if i%2 ==0:
                    randid = random.randint(0,20) #number of consonants
                    ret += consonants[randid]
                else:
                    randid = random.randint(0,4) #number of vowels
                    ret += vowels[randid]
            return ret
        
        def n_part(slen):
            ret = ''
            for i in range(slen):
                randid = random.randint(0,9) #number of digits
                ret += digits[randid]
            return ret
            
        #### 	
        fpl = alpha/2		
        if alpha % 2 :
            fpl = int(alpha/2) + 1 					
        lpl = alpha - fpl	
        
        start = a_part(fpl)
        mid = n_part(numeric)
        end = a_part(lpl)
        
        return "%s%s%s" % (start,mid,end)

    def hashPassword(self, password):
        _pver = sys.version.split()[0]
        if version.LooseVersion(_pver) < version.LooseVersion('2.5.0'):
            import md5
            return md5.new(password).hexdigest()
        else:
            import hashlib
            return hashlib.md5(password).hexdigest()

    def storePassword(self, client, pwdhash):
        self.console.storage.query(QueryBuilder(self.console.storage.db).UpdateQuery( { 'password' : pwdhash }, 'clients', { 'id' : client.id } ))

    def storeEmail(self, client, email):
        self.console.storage.query(QueryBuilder(self.console.storage.db).UpdateQuery( { 'login' : email }, 'clients', { 'id' : client.id } ))

    def testAvail(self):
        if not self.privateMsg and not self.sendMail:
            self.info("We can't send emails or a private message to the client, disabling the plugin")
            self.enable = False
            return

    def checkEmail(self, data):
        if len(data) == 0:
            return 'None'
        if not self.sendMail:
            return "Sending emails is not enabled!"
        monster = "(?:[a-z0-9!#$%&'*+/=?^_{|}~-]+(?:.[a-z0-9!#$%" + \
            "&'*+/=?^_{|}~-]+)*|\"(?:" + \
            "[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]" + \
            "|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9]" + \
            "(?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" + \
            "|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)" + \
            "{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?" + \
            "|[a-z0-9-]*[a-z0-9]:(?:" + \
            "[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]"  + \
            "|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"
        email = re.compile(monster)
        if len(data) > 7:
            if email.match(data):
                return 'Valid'
        else:
            return "Email address is not valid"

    def sendMail(self, client, password, toaddr):
        text = self._introduction
        text += ("\r\n\r\nID for login: %s\r\n" %client.id)
        text += ("Password: %s\r\n\r\n" %password)
        text += self._tail
        
        msg = MIMEText(text)
        msg['To'] = toaddr
        msg['From'] = self._fromAddress
        msg['Subject'] = self._subject
        
        try:
            server = smtplib.SMTP(self._host)
            server.set_debuglevel(0)
            server.sendmail(self._fromAddress, toaddr, msg.as_string())
            server.quit()
            client.message('Password sent to %s' %toaddr)
        except Exception, msg:
            self.error('Sending email failed: %s' %msg)
            client.message('Sending email failed: %s' %msg)
            #(111, 'Connection refused')
            if msg[0] == 111:
                self.sendMail = False
                self.testAvail()

if __name__ == '__main__':
    print '\nThis is version '+__version__+' by '+__author__+' for BigBrotherBot.\n'
