from collector.malware import *

bazaar = MalwareBazaar()

# set the start, end pair in the PE malware info list
bazaar.download_sample(5000,30000)
