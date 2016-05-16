'''
Created on 30. 7. 2015

@author: vojta
'''

import os

class ContentIdentifier():
    def __init__(self):
        self.accepted_types = []
        self.rejected_types = []
        self.CONFIGDIR = ".requestcapturer"
        self.CONFIGPATH = os.path.expanduser("~/"+self.CONFIGDIR)
        if os.path.exists(self.CONFIGPATH) == False:
            print ("Configuration directory does not exist, trying to create one...")
            os.mkdir(self.CONFIGPATH)
        try:
            tmp = open(os.path.join(self.CONFIGPATH, "content-types.accepted"), "r")
            for l in tmp:
                self.accepted_types.append(l[:-1])
            tmp.close()
        except IOError:
            print("No file with accepted content types found.\n")
        try:
            tmp = open (os.path.join(self.CONFIGPATH, "content-types.rejected"), "r")
            for l in tmp:
                self.rejected_types.append(l[:-1])
            tmp.close()
        except IOError:
            print ("No file with rejected content types found.\n")

    def shutdown(self):
        try:
            accfile = open(os.path.join(self.CONFIGPATH, "content-types.accepted"), "w")
            for c in self.accepted_types: accfile.write(c+"\n")
            accfile.close()
        except IOError:
            print("Can not write accepted content types into file!")
        try:
            rejfile = open(os.path.join(self.CONFIGPATH, "content-types.rejected"), "w")
            for c in self.rejected_types:
                rejfile.write(c+"\n")
            rejfile.close()
        except IOError:
            print("Can not write rejected requests into file!")

    def identifyContent(self, ctype, viewfunc, msg):
        """ tries to accept/reject content-type based on stored values in files. If it can't find a match, it asks. In this case it can throw KeyboardInterruptError.
        """
        notype = False
        if ctype == None:
            print ("This message does not contain any Content-Type header. It might be regular HTTP message or some garbage data. I won't store such content type into any file, but I may let it pass or not.")
            notype = True
        if ctype in self.accepted_types:
            return True
        elif ctype in self.rejected_types:
            return False
        else:
            while True:
                ans = raw_input("Encountered unknown content-type {0}. Accept/Reject/View content?\n".format(ctype))
                if ans.lower() == 'a':
                    if notype == False:
                        self.accepted_types.append(ctype)
                    else:
                        return True
                    break
                elif ans.lower() == 'r':
                    if notype == False:
                        self.rejected_types.append(ctype)
                    else:
                        return False
                    break
                if ans.lower() == 'v':
                    print (viewfunc(msg))
                    print ("Content may contain problematic data, recommend to reject!\n")
            return self.identifyContent(ctype, viewfunc, msg) #to finally accept or reject the ctype
