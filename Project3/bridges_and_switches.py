from mininet.cli import CLI
from mininet.link import Link, TCLink
from mininet.net import Mininet

if '__main__' == __name__:
    net = Mininet(link=TCLink)

    h1 = net.addHost('h1', ip='50.0.0.1', mac='00:00:00:00:01:00')
    h2 = net.addHost('h2', ip='50.0.0.2', mac='00:00:00:00:02:00')
    h3 = net.addHost('h3', ip='50.0.0.3', mac='00:00:00:00:03:00')
    h4 = net.addHost('h4', ip='50.0.0.4', mac='00:00:00:00:04:00')

    bridge = net.addHost('bridge', ip='50.0.0.8', mac='00:00:00:00:08:00')

    Link(h1, bridge)
    Link(h2, bridge)
    Link(h3, bridge)
    Link(h4, bridge)

    net.build()

    bridge.cmd("ifconfig bridge-eth0 0")
    bridge.cmd("ifconfig bridge-eth1 0")
    bridge.cmd("ifconfig bridge-eth2 0")
    bridge.cmd("ifconfig bridge-eth3 0")

    bridge.cmd("brctl addbr br0")

    bridge.cmd('brctl addif br0 bridge-eth0')
    bridge.cmd('brctl addif br0 bridge-eth1')
    bridge.cmd('brctl addif br0 bridge-eth2')
    bridge.cmd('brctl addif br0 bridge-eth3')

    bridge.cmd("ifconfig br0 up")

    print(bridge.cmd('brctl showmacs br0'))
    net.pingAll()

    # Task 2
    # To run task 2 make sure to comment out the task 3 code lines
    bridge.cmd('bridge monitor fdb >> bridge_logs.txt &')

    h1.cmd("tcpdump -n -e -i h1-eth0 >> h1logs.txt &")
    h2.cmd("tcpdump -n -e -i h2-eth1 >> h2logs.txt &")
    h3.cmd("tcpdump -n -e -i h3-eth2 >> h3logs.txt &")
    h4.cmd("tcpdump -n -e -i h4-eth3 >> h4logs.txt &")

    # Task 3
    # To run task 3 make sure to comment out the tcp dump lines and the net.pingAll()
    # verifying to check if we can reach h3 and h4 from h1 and h2
    h1.cmd('ping -c 1 h3')
    h2.cmd('ping -c 1 h4')

    h1.cmd('iperf -s > h1.log &')
    h2.cmd('iperf -s > h2.log &')

    h3.cmd('iperf -c 50.0.0.1 -i 10 -t 10 > h1_h3_result.txt &')
    h4.cmd('iperf -c 50.0.0.2 -i 10 -t 10 > h2_h4_result.txt &')

    net.waitConnected()

    # Task 3 ended on line 64
    CLI(net)

    net.stop()
