from mininet.topo import Topo
from mininet.link import TCLink

#Topology class
class Topologi( Topo ):
    "Topologi"
    def build( self ):
        # Add hosts client and server
        h1 = self.addHost('h1',mac='00:00:00:00:00:01')
        h2 = self.addHost('h2',mac='00:00:00:00:00:02')
        h3 = self.addHost('h3',mac='00:00:00:00:00:03')
        h4 = self.addHost('h4',mac='00:00:00:00:00:04')
        h5 = self.addHost('h5',mac='00:00:00:00:00:05')

        # Add switches
        s1 = self.addSwitch('s1',)

        # Add links
        self.addLink(s1,h1,cls=TCLink,bw=100,delay='40ms')
        self.addLink(s1,h2,cls=TCLink,bw=100,delay='40ms')
        self.addLink(s1,h3,cls=TCLink,bw=100,delay='40ms')
        self.addLink(s1,h4,cls=TCLink,bw=100,delay='40ms')
        self.addLink(s1,h5,cls=TCLink,bw=100,delay='40ms')

topos = {'mytopo': (lambda: Topologi())}