from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.cli import CLI
import sys
from mininet.term import makeTerm
from topologi import Topologi

#Fungsi untuk run network
def runNet():
    topo = Topologi()
    net = Mininet(topo, controller=RemoteController)
    net.start() #Run network
    
    # #Buat server
    # server = []
    # for i in range(1,8):
    # server.append(net.get("h"+str(i)))
    # #Run server di h1 - h7
    # for i in range(len(server)):
    # server[i].cmd("python3 -m http.server 80 &")
    # print("Python HTTP Server with port 80 is running on h"+str(i+1))
    
    server = []
    process = []
    for i in range(1,3):
        server.append(net.get("h"+str(i)))
        
    if(sys.argv[1] == 'html'):
        for i in range(len(server)):
            process.append(makeTerm(server[i], cmd="sudo bash ./webServer.sh "+str(i+1)))
    else:
        for i in range(len(server)):
            process.append(makeTerm(server[i], cmd="sudo bash ./picServer.sh "))
            
    CLI(net)
    net.stop()
    
if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    runNet()