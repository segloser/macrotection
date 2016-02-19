#!/usr/bin/python

###########################################  LICENSE  ################################################
"""This license applies to the python-oletools package, apart from the thirdparty folder which contains 
third-party files published with their own license.

The python-oletools package is copyright (c) 2012-2015 Philippe Lagadec (http://www.decalage.info)

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
 provided that the following conditions are met:

	Redistributions of source code must retain the above copyright notice, 
	this list of conditions and the following disclaimer.
	Redistributions in binary form must reproduce the above copyright notice,
	this list of conditions and the following disclaimer in the documentation 
	and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."""
#######################################  END OF LICENSE TERMS  ########################################

__author__ = 'info@segloser.com (Eduardo ORENES)'
__version__ = '0.1'
__copyright__ = 'Read above, since I have just joint some pieces together'
__license__ = 'Read above'

print "We are going to install oletools first"
import os
os.system('pip install oletools')

from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
import sys
import Tkinter
from tkFileDialog import askopenfilename
import tkMessageBox
import time

# Reseting the outputfile
reset = open("output.txt", "w")
reset.write('')
reset.close()

# Cleaning the screen and showing some general info about the use
print(chr(27) + "[2J")
print "Using this tool is simple. Just read and follow the progressive instructions shown"
print "\n\nFor your convenience, copy the suspicious file in the same directory\
 \nof the tool.\n\n "

# suspicious = raw_input("Enter the entire path of the suspicious file, please: ")
print("The entire path of the suspicious file is: ")

# suspicious and indicator as global variables
global suspicious
global indicator

def sus_call():
	global suspicious
	file_to_open = askopenfilename()
	suspicious = file_to_open
	print suspicious
	print "Go to the already open window and click <Start Analysis>"
	return suspicious

# Window to select a file for analysis
errmsg = 'Error!'
file_win = Tkinter.Tk()
D = Tkinter.Button(	text = 'Choose a file',
			fg = 'darkgreen',
			command = sus_call)
D.pack()
Tkinter.Button(		text = 'Start Analysis',
			fg = 'darkorange',
			command = file_win.quit).pack()
file_win.mainloop()

#vbaparser = VBA_Parser(sys.argv[1])
vbaparser = VBA_Parser(suspicious)
#sus_file = sys.argv[1] # sus_file suspicious_file
sus_file = suspicious
## Other way to do the same
sus_filedata = open(sus_file, 'rb').read()
vbaparser = VBA_Parser(sus_file, data=sus_filedata)

## Manual Macro extraction details
##for (sys.argv[1], stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
##	print '-' * 79
##	print 'Filename        :', sys.argv[1]
##	print 'OLE stream      :', stream_path
##	print 'VBA filename    :', vba_filename
##	print '- ' * 39
##	print vba_code


# Macros analysis
global results
results = vbaparser.analyze_macros()
def show_message_macro_analysis():
	print ' ' * 40 + '==============='
	print ' ' * 40 + 'Macros analysis'
	print ' ' * 40 + '===============\n\n'

def show_message_keywords():
	print '   Type\t\tKeyword\t\t                      Description' 
	print '==========\t==========\t\t========================================================='
	for kw_type, keyword, description in results:
		print '%s\t%s\t\t\t%s'% (kw_type, keyword, description)
	print '\n\n'

def show_message_indicators():
	print '=' * 35
	print 'AutoExec keywords: %d' % vbaparser.nb_autoexec
	print 'Suspicious keywords: %d' % vbaparser.nb_suspicious
	print 'IOCs: %d' % vbaparser.nb_iocs
	print 'Hex obfuscated strings: %d' % vbaparser.nb_hexstrings
	print 'Base64 obfuscated strings: %d' % vbaparser.nb_base64strings
	print 'Dridex obfuscated strings: %d' % vbaparser.nb_dridexstrings
	print 'VBA obfuscated strings: %d' % vbaparser.nb_vbastrings
	print '=' * 35

	global indicator
	indicator = 0
	if vbaparser.nb_autoexec > 0 or vbaparser.nb_suspicious > 0 or vbaparser.nb_iocs > 0 or vbaparser.nb_hexstrings > 0 or vbaparser.nb_base64strings > 0 or vbaparser.nb_vbastrings > 0 or vbaparser.nb_dridexstrings > 0:
		indicator += 1
		print "\n\n\033[91mPlease, this file presents certain indicators that should be carefully reviewed.\033[0m"
		print "\033[91mStop any action, lock the screen and call a security specialist\033[0m"
		print "\033[91mIf you are alone, do not execute this file until examined by a professional\033[0m"
	if vbaparser.nb_dridexstrings > 0:
		indicator += 1
		print "\n\n\033[91mAt least one Dridex indicator has been found. Call your security department and DO NOT EXECUTE THIS FILE\033[0m"
	return indicator

## Some info from deobfuscation (if successful)
def show_message_deobfuscation():
        reveal_file = open('raw_report.txt', 'w')
        reveal_file.write(vbaparser.reveal())
        reveal_file.close()
        print "\n\nA file named <raw_report.txt> contains the details of the deobfuscation try (for expert users)"
        print "If not sure about the next steps, provide a copy of this file to your security advisor to avoid trojan/virus infection risks"
        print "Thanks for using this tool and for preserving your digital environment from malware\n\n\n"

def show_joint_messages():
	show_message_macro_analysis()
	show_message_keywords()
	show_message_indicators()
	show_message_deobfuscation()

# printing results in stdout
show_joint_messages() # put outcome into text file	
sys.stdout = open('output.txt', 'a')
print show_joint_messages()

# Section to warn about dangerous indicators
if indicator > 0:
        print(chr(27) + "[2J")
        print"\n\n\n\n\t\t\t\t=============================="
        print "\t\t\t\t\033[91m     ALERT\033[0m"
        print "\t\t\t\t\033[91mMalicious Indicators Detected\033[0m"
        print "\t\t\t\t==============================\n\n\n\n"
        print "\n\n \033[91mPlease, take the time to understand that this file could be a potential risk for your organization\033[0m\n\n"

else:
        print "We have NOT found VBA Macros, but proceed with caution concerning links"
        print "Please, check a link before clicking on it, especially, if the sender is unknown\n\n"

sys.stdout.close()

# DO NOT FORGET TO CLOSE THE VBAPARSER
vbaparser.close()

#GUI part
top = Tkinter.Tk()
output = open("output.txt", "r")
con_out = output.read()
output.close()
def helloCallBack():
	tx_tk = Tkinter.Tk()
	text = Tkinter.Text(tx_tk, height = 500, width = 500)
	text.pack()
        text.insert(Tkinter.INSERT, con_out)
	tx_tk.mainloop()
	#tkMessageBox.showinfo("Built for you by SIA GROUP") #, show_joint_messages())

B = Tkinter.Button(	top, 
			text = "Click here to see the results of the analysis!", 
			fg ='darkred',
			command = helloCallBack)
Tkinter.Button(		text = 'Click Twice Here to Exit',
			fg = 'darkred',
			command = top.quit).pack()
B.pack()
top.geometry('500x500')
top.mainloop()
